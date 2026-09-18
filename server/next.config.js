/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: {
      enabled: true,
    },
  },
  // mTLS proxy passes agent identity via header
  async headers() {
    return [
      {
        source: '/api/ingest/:path*',
        headers: [
          {
            key: 'X-Client-Cert-Verified',
            value: 'SUCCESS',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
