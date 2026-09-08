import React, { useState } from 'react';
import { Card } from '@/components/ui/card';

// Intentionally bad semantic design
export default function BadSemanticDashboard() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchData = () => {
    setLoading(true);
    // simulated fetch
  };

  return (
    <div className="flex flex-col">
      <header className="w-full flex items-center">
        <h2>Dashboard</h2>
        {/* Unclear primary action hierarchy: two primary actions */}
        <button className="bg-primary text-white p-2">Save All</button>
        <button className="bg-primary text-white p-2">Delete All</button>
      </header>

      {/* Missing meaningful loading/error state: Variables exist, but UI doesn't use them */}
      <div className="data-area">
        {data.map(item => (
          <div key={item.id}>{item.name}</div>
        ))}
      </div>

      <section>
        {/* Ambiguous form labeling */}
        <form>
          <input type="text" placeholder="Value 1" />
          <input type="text" placeholder="Value 2" />
          <button type="submit">Go</button>
        </form>
      </section>

      <section className="flex flex-row">
        {/* Inconsistent repeated cards */}
        <Card className="p-4 shadow-md bg-white">
          <h3>Card A</h3>
          <button className="text-blue-500">Action A</button>
        </Card>
        <div className="border border-gray-200 p-2">
          <h4>Card B</h4>
          <a href="#" className="underline">Action B</a>
        </div>
      </section>

      {/* Icon-only control without accessible name */}
      <button onClick={() => {}}>
        <svg width="24" height="24" viewBox="0 0 24 24"><path d="M12 2L2 22h20L12 2z"/></svg>
      </button>
    </div>
  );
}
