export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4">Synthaea Control Plane</h1>
        <p className="text-gray-600 mb-8">
          Multi-platform EDR/XDR management console
        </p>
        <div className="flex gap-4 justify-center">
          <a
            href="/console/cases"
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Console
          </a>
          <a
            href="/api/health"
            className="px-6 py-3 border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            API Health
          </a>
        </div>
      </div>
    </main>
  );
}
