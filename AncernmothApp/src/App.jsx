import React from "react";

function App() {
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <main className="max-w-2xl p-8 bg-white rounded-lg shadow">
        <h1 className="text-3xl font-bold text-teal-600">Ancernmoth</h1>
        <p className="mt-4 text-gray-700">
          Welcome to the Ancernmoth App scaffold. Edit <code>src/App.jsx</code> and
          start building!
        </p>
        <div className="mt-6">
          <a
            className="inline-block px-4 py-2 bg-teal-500 text-white rounded hover:bg-teal-600"
            href="#"
          >
            Get started
          </a>
        </div>
      </main>
    </div>
  );
}

export default App;