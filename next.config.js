/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async redirects() {
    return [
      { source: '/secure', destination: '/', permanent: false },
      { source: '/about', destination: '/', permanent: false },
      { source: '/about/:path*', destination: '/', permanent: false },
      { source: '/blog', destination: '/', permanent: false },
      { source: '/blog/:path*', destination: '/', permanent: false },
      { source: '/docs', destination: '/', permanent: false },
      { source: '/docs/:path*', destination: '/', permanent: false },
      { source: '/pricing', destination: '/', permanent: false },
      { source: '/pricing/:path*', destination: '/', permanent: false },
    ]
  },
}

module.exports = nextConfig
