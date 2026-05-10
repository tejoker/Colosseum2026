import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  transpilePackages: ["snarkjs"],
  async rewrites() {
    const dashboardOrigin = process.env.DASHBOARD_INTERNAL_URL || "http://localhost:8003";

    return [
      {
        source: "/dashboard/:path*",
        destination: `${dashboardOrigin}/:path*`,
      },
    ];
  },
};

export default nextConfig;
