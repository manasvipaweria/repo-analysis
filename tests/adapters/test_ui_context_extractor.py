import os
import subprocess
import pytest

def test_extract_ui_context_basic(tmp_path):
    # Create a small React component
    react_file = tmp_path / "Button.jsx"
    react_file.write_text("""
import React, { useState } from 'react';

export function ComplexButton() {
    const [isHovered, setIsHovered] = useState(false);
    
    const handleMouseOver = () => setIsHovered(true);
    const handleMouseOut = () => setIsHovered(false);
    
    return (
        <button 
            className={`btn ${isHovered ? 'active' : ''}`}
            onMouseOver={handleMouseOver}
            onMouseOut={handleMouseOut}
        >
            {isHovered && <span className="icon">🔥</span>}
            Click Me
        </button>
    );
}
    """, encoding="utf-8")

    extractor_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
        "src", "adapters", "extract_ui_context.js"
    )
    
    result = subprocess.run(
        ["node", extractor_script, str(react_file)], 
        capture_output=True, text=True, check=True
    )
    
    output = result.stdout
    assert "Component: ComplexButton" in output
    assert "State: isHovered" in output
    assert "Actions: handleMouseOver, handleMouseOut" in output
    assert "<button className=" in output
    assert "<span className=\"icon\">" in output

def test_extract_ui_context_nested_hierarchy(tmp_path):
    react_file = tmp_path / "Layout.jsx"
    react_file.write_text("""
import React from 'react';

const Sidebar = () => <nav className="sidebar"><ul><li>Link</li></ul></nav>;

export const Dashboard = () => {
    const isReady = true;
    return (
        <div className="dashboard-root">
            <Sidebar />
            <main id="main-content">
                {isReady && <section className="data">Data</section>}
            </main>
        </div>
    );
}
    """, encoding="utf-8")

    extractor_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
        "src", "adapters", "extract_ui_context.js"
    )
    
    result = subprocess.run(
        ["node", extractor_script, str(react_file)], 
        capture_output=True, text=True, check=True
    )
    
    output = result.stdout
    # Check Sidebar component extraction
    assert "Component: Sidebar" in output
    assert "<nav className=\"sidebar\">" in output
    
    # Check Dashboard component extraction
    assert "Component: Dashboard" in output
    assert "<div className=\"dashboard-root\">" in output
    assert "<Sidebar>" in output
    assert "Condition: isReady" in output
    assert "<section className=\"data\">" in output
