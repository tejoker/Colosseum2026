/// Commitment ledger backed by a Merkle tree.
///
/// Chaque "feuille" est le SHA256 d'un secret client (le commitment).
/// Sauron s'engage cryptographiquement sur l'ensemble des KYC reçus :
/// en cas de litige, le client peut prouver mathématiquement que son
/// KYC a bien été ingéré par Sauron sans révéler aucune base de données.
///
/// Internal algorithm: standard SHA256, suitable for Bitcoin OP_RETURN commitments.
use rs_merkle::{algorithms::Sha256 as MerkleSha256, MerkleTree};

/// Ledger immuable (append-only) des commitments KYC.
/// Vit en mémoire dans ServerState ; reconstruit depuis la DB au démarrage.
pub struct MerkleCommitmentLedger {
    /// Toutes les feuilles insérées, dans l'ordre d'arrivée.
    /// Chaque feuille est le commitment brut (32 octets), NON re-hashé ici
    /// car le client l'a déjà produit via SHA256(secret).
    leaves: Vec<[u8; 32]>,
    /// L'arbre rs_merkle sous-jacent.
    tree: MerkleTree<MerkleSha256>,
}

/// Résultat d'une insertion de commitment.
pub struct CommitmentReceipt {
    /// Index de la feuille dans l'arbre (0-based).
    pub leaf_index: usize,
    /// Nombre total de feuilles dans l'arbre après insertion.
    pub total_leaves: usize,
    /// Racine de Merkle (hex 64 caractères).
    pub merkle_root: String,
    /// Chemin de preuve : hashes frères de la feuille vers la racine (hex).
    pub merkle_proof: Vec<String>,
}

impl MerkleCommitmentLedger {
    /// Crée un ledger vide.
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            tree: MerkleTree::<MerkleSha256>::new(),
        }
    }

    /// Ajoute un commitment, le committe dans l'arbre, et retourne la preuve.
    ///
    /// `commitment_hex` : SHA256 hex d'un secret client (64 caractères = 32 octets).
    ///
    /// Retourne `Err(String)` si le hex est invalide ou ne fait pas 32 octets.
    pub fn add_commitment(&mut self, commitment_hex: &str) -> Result<CommitmentReceipt, String> {
        let bytes =
            hex::decode(commitment_hex).map_err(|e| format!("commitment hex invalide : {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "commitment doit être 32 octets (SHA256), reçu {} octets",
                bytes.len()
            ));
        }
        let leaf: [u8; 32] = bytes.try_into().unwrap();

        // Insérer et committer.
        self.tree.insert(leaf);
        self.tree.commit();
        self.leaves.push(leaf);

        let leaf_index = self.leaves.len() - 1;
        let total_leaves = self.leaves.len();

        // Calculer la racine.
        let root_bytes = self
            .tree
            .root()
            .ok_or_else(|| "impossible de calculer la racine Merkle".to_string())?;
        let merkle_root = hex::encode(root_bytes);

        // Générer la preuve pour cette feuille.
        let proof = self.tree.proof(&[leaf_index]);
        let merkle_proof: Vec<String> = proof.proof_hashes().iter().map(hex::encode).collect();

        Ok(CommitmentReceipt {
            leaf_index,
            total_leaves,
            merkle_root,
            merkle_proof,
        })
    }

    /// Retourne la racine actuelle, ou None si l'arbre est vide.
    pub fn root_hex(&self) -> Option<String> {
        self.tree.root().map(hex::encode)
    }

    /// Nombre de commitments dans le ledger.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Reconstruit le ledger depuis une liste ordonnée de commitments hex
    /// (tels que stockés dans la table `merkle_leaves` en DB).
    ///
    /// Les feuilles sont réinsérées dans l'ordre chronologique et committées
    /// d'un seul coup pour l'efficacité.
    pub fn from_db_leaves(ordered_commitments: Vec<String>) -> Result<Self, String> {
        let mut ledger = Self::new();
        if ordered_commitments.is_empty() {
            return Ok(ledger);
        }

        for hex_str in &ordered_commitments {
            let bytes = hex::decode(hex_str)
                .map_err(|e| format!("feuille DB corrompue '{}' : {}", hex_str, e))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "feuille DB invalide : {} octets au lieu de 32",
                    bytes.len()
                ));
            }
            let leaf: [u8; 32] = bytes.try_into().unwrap();
            ledger.tree.insert(leaf);
            ledger.leaves.push(leaf);
        }
        // Un seul commit groupé pour la reconstruction.
        ledger.tree.commit();

        let count = ledger.leaves.len();
        println!(
            "[MERKLE] Ledger reconstruit depuis DB : {} feuille(s) | root={}",
            count,
            ledger.root_hex().unwrap_or_else(|| "∅".to_string())
        );
        Ok(ledger)
    }
}

impl Default for MerkleCommitmentLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rs_merkle::{algorithms::Sha256 as MerkleSha256, MerkleProof};
    use sha2::{Digest, Sha256};

    /// Helper: produce a 32-byte commitment hex string from a label.
    fn commitment_hex_for(label: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(label);
        hex::encode(h.finalize())
    }

    #[test]
    fn test_merkle_new_ledger_is_empty() {
        let ledger = MerkleCommitmentLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert!(ledger.root_hex().is_none());
    }

    #[test]
    fn test_merkle_build_root_single_leaf() {
        let mut ledger = MerkleCommitmentLedger::new();
        let c = commitment_hex_for(b"leaf-0");
        let receipt = ledger.add_commitment(&c).expect("insert");
        assert_eq!(receipt.leaf_index, 0);
        assert_eq!(receipt.total_leaves, 1);
        assert_eq!(receipt.merkle_root.len(), 64);
        // Single leaf: root equals the leaf itself in rs_merkle's SHA256 algo.
        assert_eq!(receipt.merkle_root, c);
        // Proof for single leaf is empty (no siblings).
        assert!(receipt.merkle_proof.is_empty());
    }

    #[test]
    fn test_merkle_build_root_two_leaves_changes() {
        let mut ledger = MerkleCommitmentLedger::new();
        let r1 = ledger
            .add_commitment(&commitment_hex_for(b"leaf-A"))
            .expect("insert A")
            .merkle_root;
        let r2 = ledger
            .add_commitment(&commitment_hex_for(b"leaf-B"))
            .expect("insert B")
            .merkle_root;
        assert_ne!(r1, r2, "root must change when a new leaf is added");
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn test_merkle_build_root_three_leaves_has_proof() {
        let mut ledger = MerkleCommitmentLedger::new();
        for i in 0..3 {
            let _ = ledger
                .add_commitment(&commitment_hex_for(format!("leaf-{i}").as_bytes()))
                .expect("insert");
        }
        assert_eq!(ledger.len(), 3);
        let root = ledger.root_hex().expect("root present");
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_merkle_build_root_one_thousand_leaves() {
        let mut ledger = MerkleCommitmentLedger::new();
        let mut last_root = String::new();
        for i in 0..1000 {
            let r = ledger
                .add_commitment(&commitment_hex_for(
                    format!("bulk-leaf-{i}").as_bytes(),
                ))
                .expect("insert");
            assert_eq!(r.leaf_index, i);
            assert_eq!(r.total_leaves, i + 1);
            last_root = r.merkle_root;
        }
        assert_eq!(ledger.len(), 1000);
        assert_eq!(ledger.root_hex().unwrap(), last_root);
    }

    #[test]
    fn test_merkle_proof_verifies_for_inserted_leaf() {
        // Build a 5-leaf tree and verify the proof for leaf #2 reconstructs the root.
        let mut ledger = MerkleCommitmentLedger::new();
        let leaves_hex: Vec<String> = (0..5)
            .map(|i| commitment_hex_for(format!("verify-{i}").as_bytes()))
            .collect();
        let mut last_receipt = None;
        for h in &leaves_hex {
            last_receipt = Some(ledger.add_commitment(h).expect("insert"));
        }
        let final_root_hex = last_receipt.unwrap().merkle_root;

        // Re-fetch proof for leaf 2 via the underlying tree (the public API only
        // returns the proof captured at insertion time, so re-add a fresh ledger).
        let leaf_bytes: Vec<[u8; 32]> = leaves_hex
            .iter()
            .map(|h| hex::decode(h).unwrap().try_into().unwrap())
            .collect();
        let mut tree = rs_merkle::MerkleTree::<MerkleSha256>::new();
        for lb in &leaf_bytes {
            tree.insert(*lb);
        }
        tree.commit();
        let proof = tree.proof(&[2]);
        let root_bytes: [u8; 32] = tree.root().unwrap();
        assert_eq!(hex::encode(root_bytes), final_root_hex);

        let ok = proof.verify(root_bytes, &[2], &[leaf_bytes[2]], leaf_bytes.len());
        assert!(ok, "valid proof must verify against the published root");
    }

    #[test]
    fn test_merkle_proof_rejects_tampered_leaf() {
        // Build proof for a known leaf, then flip a bit and confirm verify fails.
        let mut tree = rs_merkle::MerkleTree::<MerkleSha256>::new();
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut h = Sha256::new();
                h.update(format!("tamper-{i}").as_bytes());
                h.finalize().into()
            })
            .collect();
        for l in &leaves {
            tree.insert(*l);
        }
        tree.commit();
        let root: [u8; 32] = tree.root().unwrap();
        let proof = tree.proof(&[1]);

        // Honest verify: passes.
        assert!(proof.verify(root, &[1], &[leaves[1]], leaves.len()));

        // Tamper: flip the first bit of leaf #1.
        let mut tampered = leaves[1];
        tampered[0] ^= 0x01;
        assert!(
            !proof.verify(root, &[1], &[tampered], leaves.len()),
            "tampered leaf must NOT verify against the original root"
        );

        // Also check that the proof bytes round-trip but a wrong root rejects.
        let mut bogus_root = root;
        bogus_root[0] ^= 0x80;
        let proof_bytes = proof.to_bytes();
        let reparsed = MerkleProof::<MerkleSha256>::from_bytes(&proof_bytes).unwrap();
        assert!(!reparsed.verify(bogus_root, &[1], &[leaves[1]], leaves.len()));
    }

    #[test]
    fn test_merkle_add_commitment_rejects_invalid_hex() {
        let mut ledger = MerkleCommitmentLedger::new();
        match ledger.add_commitment("zznothex") {
            Err(err) => assert!(err.contains("hex invalide"), "got: {err}"),
            Ok(_) => panic!("invalid hex must be rejected"),
        }
    }

    #[test]
    fn test_merkle_add_commitment_rejects_wrong_length() {
        let mut ledger = MerkleCommitmentLedger::new();
        // 16 bytes hex == 32 chars; expected 64 chars / 32 bytes.
        match ledger.add_commitment(&"ab".repeat(16)) {
            Err(err) => assert!(err.contains("32 octets"), "got: {err}"),
            Ok(_) => panic!("short commitment must be rejected"),
        }
    }

    #[test]
    fn test_merkle_from_db_leaves_empty_returns_empty_ledger() {
        let ledger = MerkleCommitmentLedger::from_db_leaves(Vec::new()).expect("empty ok");
        assert!(ledger.is_empty());
        assert!(ledger.root_hex().is_none());
    }

    #[test]
    fn test_merkle_from_db_leaves_reconstructs_same_root() {
        // Build a ledger A by sequential inserts, build a ledger B by from_db_leaves,
        // both must yield identical roots.
        let hexes: Vec<String> = (0..7)
            .map(|i| commitment_hex_for(format!("restore-{i}").as_bytes()))
            .collect();

        let mut a = MerkleCommitmentLedger::new();
        for h in &hexes {
            a.add_commitment(h).unwrap();
        }
        let root_a = a.root_hex().unwrap();

        let b = MerkleCommitmentLedger::from_db_leaves(hexes.clone()).unwrap();
        let root_b = b.root_hex().unwrap();

        assert_eq!(root_a, root_b);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn test_merkle_from_db_leaves_rejects_corrupt_hex() {
        let bad = vec!["not-hex".to_string()];
        match MerkleCommitmentLedger::from_db_leaves(bad) {
            Err(err) => assert!(err.contains("corrompue"), "got: {err}"),
            Ok(_) => panic!("corrupt hex must be rejected"),
        }
    }
}
