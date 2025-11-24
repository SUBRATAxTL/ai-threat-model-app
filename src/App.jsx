import React, { useState, useEffect, useMemo, useRef } from 'react';
import { ShieldCheck, Upload, FileText, Cpu, AlertTriangle, Lightbulb, CheckCircle, Code, Server, Database, Users, ArrowRight, X, BarChart2, Zap, Download } from 'lucide-react';


// --- AI/ML ANALYSIS ENGINE (using Gemini API) ---
const aiEngine = {
  analyzeArtifacts: async (files, { signal }) => { // Accept a signal for cancellation
    const combinedContent = files.map(f => `--- FILE: ${f.name} ---\n${f.content}`).join('\n\n');

    const userQuery = `
    Analyze the following software project artifacts and generate a threat model.

    **Project Artifacts:**
    ${combinedContent}

    **Instructions:**
    1.  Identify the key assets in the system (e.g., 'User Database', 'API Gateway', 'Authentication Service'). Provide at least 3 assets.
    2.  Based on the assets and their interactions, identify potential threats.
    3.  For each threat, provide a detailed analysis using the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
    4.  Assign a severity level ('Critical', 'High', 'Medium', 'Low') to each threat.
    5.  Pinpoint the affected component (must be one of the identified assets) for each threat.
    6.  Suggest a detailed mitigation strategy.
    7.  Provide a relevant, concise code snippet in an appropriate language demonstrating the mitigation principle.

    You must return ONLY a single valid JSON object matching the provided schema. Do not include any other text, explanations, or markdown formatting like \`\`\`json.
    `;

    const schema = {
      type: "OBJECT",
      properties: {
        assets: {
          type: "ARRAY",
          description: "A list of key assets identified in the system.",
          items: { type: "STRING" }
        },
        threats: {
          type: "ARRAY",
          description: "A list of identified threats based on the STRIDE framework.",
          items: {
            type: "OBJECT",
            properties: {
              category: { 
                  type: "STRING", 
                  description: "STRIDE category.",
                  enum: ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"] 
              },
              threat: { type: "STRING", description: "A concise description of the threat." },
              severity: { 
                  type: "STRING", 
                  description: "The assessed severity of the threat.",
                  enum: ["Critical", "High", "Medium", "Low"] 
              },
              component: { type: "STRING", description: "The asset or component affected by this threat." },
              mitigation: { type: "STRING", description: "Recommended actions to mitigate the threat." },
              codeSnippet: { type: "STRING", description: "An example code snippet for the mitigation." }
            },
            required: ["category", "threat", "severity", "component", "mitigation", "codeSnippet"]
          }
        }
      },
      required: ["assets", "threats"]
    };

    const payload = {
      contents: [{ parts: [{ text: userQuery }] }],
      generationConfig: {
        responseMimeType: "application/json",
        responseSchema: schema,
      }
    };

    const apiKey = import.meta.env.VITE_GEMINI_API_KEY; // Canvas will provide this.
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    let response;
    let attempts = 0;
    while (attempts < 5) {
        if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
        try {
            response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal, // Pass the signal to the fetch request
            });

            if (response.ok) break;

            if (response.status === 429 || response.status >= 500) {
                attempts++;
                const delay = Math.pow(2, attempts) * 1000;
                await new Promise(res => setTimeout(res, delay));
            } else {
                throw new Error(`API request failed with status ${response.status}`);
            }
        } catch (error) {
            if (error.name === 'AbortError') {
              console.log('Fetch aborted');
              throw error; // Re-throw so the calling function knows it was aborted
            }
            if (attempts >= 4) throw error;
            attempts++;
            const delay = Math.pow(2, attempts) * 1000;
            await new Promise(res => setTimeout(res, delay));
        }
    }

    if (!response || !response.ok) {
        if (signal.aborted) {
             throw new DOMException('Aborted', 'AbortError');
        }
        const errorBody = response ? await response.text() : 'No response from server';
        console.error("API Error Response:", errorBody);
        throw new Error(`API request failed with status ${response ? response.status : 'unknown'}`);
    }

    const result = await response.json();
    
    const candidate = result.candidates?.[0];
    if (!candidate || !candidate.content?.parts?.[0]?.text) {
        console.error("Invalid response structure from API:", result);
        throw new Error("Received an invalid or empty response from the AI model.");
    }
    
    const llmResponse = JSON.parse(candidate.content.parts[0].text);

    let analysis = {
      assets: new Set(llmResponse.assets || []),
      threats: (llmResponse.threats || []).map((t, i) => ({ ...t, id: Date.now() + i })),
      dataFlows: [],
      diagramData: { nodes: [], edges: [] }
    };
    
    const assetArray = Array.from(analysis.assets);
    analysis.diagramData.nodes = assetArray.map((asset, i) => ({ id: (i + 1).toString(), label: asset }));

    if (assetArray.length > 1) {
        for (let i = 0; i < assetArray.length - 1; i++) {
             analysis.diagramData.edges.push({from: (i + 1).toString(), to: (i + 2).toString(), label: 'Data/API Call'});
        }
        if (assetArray.length > 2) {
             analysis.diagramData.edges.push({from: (assetArray.length).toString(), to: "1", label: 'Auth Sync'});
        }
    }
    
    analysis.dataFlows = analysis.diagramData.edges.map(e => {
        const fromNode = analysis.diagramData.nodes.find(n => n.id === e.from)?.label || 'Unknown';
        const toNode = analysis.diagramData.nodes.find(n => n.id === e.to)?.label || 'Unknown';
        return `${fromNode} -> ${toNode} (${e.label})`
    });

    return analysis;
  }
};


// --- STYLES COMPONENT ---
const Styles = () => (
  <style>{`
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
    
    :root {
      --color-bg: #F7F7F7;
      --color-bg-dark: #FFFFFF;
      --color-text: #212529;
      --color-text-muted: #8C9BA5;
      --color-primary: #2A79A5;
      --color-medium-blue: #6B8BA4;
      --color-success: #28a745;
      --color-warning: #ffc107;
      --color-danger: #dc3545;
      --color-border: #dee2e6;
      --color-black: #000000;
      --font-family: 'Inter', sans-serif;
    }

    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: var(--font-family);
      margin: 0;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    h1, h2, h3, h4, h5, h6 {
      margin: 0;
      font-weight: 700;
    }

    .card {
      background-color: var(--color-bg-dark);
      border: 1px solid var(--color-border);
      border-radius: 8px;
      padding: 1.5rem;
      box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      font-family: var(--font-family);
      font-weight: 600;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease-in-out;
      background-color: var(--color-primary);
      color: #FFFFFF;
    }
    .btn:hover {
      filter: brightness(1.1);
    }
    .btn:disabled {
      background-color: var(--color-border);
      color: var(--color-text-muted);
      cursor: not-allowed;
    }
    .btn-secondary {
        background-color: var(--color-medium-blue);
        color: white;
    }
    .btn-danger {
        background-color: transparent;
        color: var(--color-danger);
        border: 1px solid var(--color-danger);
    }
    .btn-danger:hover {
        background-color: var(--color-danger);
        color: white;
    }

    /* Header */
    .app-header {
      background-color: var(--color-bg-dark);
      padding: 1rem 1.5rem;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--color-border);
    }
    .title-group {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .title-group h1 {
      font-size: 1.5rem;
    }

    /* File Uploader */
    .dropzone {
      border: 2px dashed var(--color-border);
      border-radius: 8px;
      padding: 2rem;
      text-align: center;
      transition: background-color 0.2s ease-in-out;
    }
    .dropzone:hover {
      background-color: rgba(0,0,0,0.03);
    }
    .file-list {
      list-style: none;
      padding: 0;
      margin-top: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .file-item {
      background-color: var(--color-bg);
      border: 1px solid var(--color-border);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    /* Analysis In Progress */
    .spinner {
      animation: spin 1s linear infinite;
      color: var(--color-primary);
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .progress-bar {
      height: 8px;
      background-color: var(--color-border);
      border-radius: 4px;
      max-width: 500px;
      margin: 2rem auto 0;
      overflow: hidden;
    }
    .progress-bar-inner {
      height: 100%;
      width: 100%;
      background-color: var(--color-primary);
      animation: progress-indeterminate 2s ease-in-out infinite;
    }
    @keyframes progress-indeterminate {
      0% { transform: translateX(-100%); } 
      100% { transform: translateX(100%); }
    }
    
    /* Threat Item & Table */
    .threat-table {
      width: 100%;
      border-collapse: collapse;
    }
    .threat-table th {
      padding: 1rem;
      text-align: left;
      font-weight: 600;
      color: var(--color-text-muted);
      border-bottom: 2px solid var(--color-border);
    }
    .threat-table tr {
      border-bottom: 1px solid var(--color-border);
    }
    .threat-table td {
      padding: 1rem;
      vertical-align: middle;
    }
    .severity-badge {
      padding: 0.25rem 0.75rem;
      border-radius: 1rem;
      font-weight: 600;
      font-size: 0.8rem;
    }
    .severity-critical { background-color: #dc354520; color: #dc3545; }
    .severity-high { background-color: #ffc10720; color: #b8860b; }
    .severity-medium { background-color: #2A79A520; color: #2A79A5; }
    .severity-low { background-color: #28a74520; color: #28a745; }

    /* Modal */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background-color: rgba(0,0,0,0.5);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }
    .modal-content {
      background-color: var(--color-bg-dark);
      border: 1px solid var(--color-border);
      border-radius: 12px;
      width: 90%;
      max-width: 800px;
      max-height: 90vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 8px 30px rgba(0,0,0,0.15);
    }
    .modal-header, .modal-footer {
      padding: 1rem 1.5rem;
    }
    .modal-header {
      border-bottom: 1px solid var(--color-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-header h5 {
      font-size: 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .modal-body {
      padding: 1.5rem;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }
    .modal-footer {
      border-top: 1px solid var(--color-border);
      text-align: right;
    }
    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 1rem;
    }
    .info-card {
      background-color: var(--color-bg);
      padding: 1rem;
    }
    .code-block {
      background-color: #212529;
      color: #f8f9fa;
      border: 1px solid var(--color-border);
      border-radius: 6px;
      padding: 1rem;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    .code-block code {
      font-family: var(--font-family);
    }
    
    /* Dashboard */
    .dashboard-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 2rem;
    }
    .dashboard-actions {
        display: flex;
        gap: 1rem;
    }
    .stats-grid {
      display: grid;
      gap: 1.5rem;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }
    .main-grid {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
      margin-top: 2rem;
    }
    .stat-card-icon {
      background-color: var(--color-bg);
      padding: 0.75rem;
      border-radius: 50%;
    }

    /* Data Flow Diagram */
    .diagram-container {
      width: 100%;
      min-height: 350px;
      background-color: var(--color-bg);
      border-radius: 6px;
      position: relative;
      margin-top: 1rem;
      border: 1px solid var(--color-border);
      overflow: hidden;
    }
    .diagram-edge {
      stroke: var(--color-medium-blue);
      stroke-width: 2;
      fill: none;
      marker-end: url(#arrowhead);
    }
    .diagram-edge-label {
      fill: var(--color-text-muted);
      font-size: 11px;
      font-weight: 600;
      text-anchor: middle;
    }
    .diagram-node-rect {
        fill: var(--color-primary);
        stroke: var(--color-bg-dark);
        stroke-width: 2;
    }
    .diagram-node-text {
        fill: white;
        font-size: 12px;
        font-weight: 600;
        text-anchor: middle;
        dominant-baseline: middle;
    }

    /* Form */
    .form-container {
      max-width: 800px;
      margin: 4rem auto;
      padding: 2rem;
    }
    .form-input {
      width: 100%;
      padding: 0.75rem 1rem;
      background-color: var(--color-bg-dark);
      border: 1px solid var(--color-border);
      color: var(--color-text);
      border-radius: 6px;
      font-family: var(--font-family);
      font-size: 1rem;
      box-sizing: border-box;
    }
    .form-input:focus {
      outline: none;
      border-color: var(--color-primary);
      box-shadow: 0 0 0 3px #2A79A540;
    }
    .alert-box {
      padding: 1rem;
      border-radius: 6px;
      margin-bottom: 1.5rem;
      border: 1px solid transparent;
    }
    .alert-danger {
      background-color: #f8d7da;
      color: #721c24;
      border-color: #f5c6cb;
    }
    .alert-warning {
      background-color: #fff3cd;
      color: #856404;
      border-color: #ffeeba;
    }
    .footer {
        text-align: center;
        color: var(--color-text-muted);
        font-size: 0.9rem;
        padding: 2rem;
        margin-top: 3rem;
        border-top: 1px solid var(--color-border);
    }
    
    .no-print {
      /* This class is used to hide elements during printing */
    }

    @media print {
      body {
        background-color: #FFFFFF;
        padding: 0;
        margin: 0;
      }
      .no-print {
        display: none !important;
      }
      .card {
        box-shadow: none;
        border: 1px solid #ccc;
        page-break-inside: avoid;
      }
      .results-printable-area {
        padding: 0;
        margin: 0;
      }
       .dashboard-header h2 {
        font-size: 1.5rem;
       }
       .threat-table {
        page-break-inside: auto;
      }
      .threat-table tr {
        page-break-inside: avoid;
        page-break-after: auto;
      }
    }
  `}</style>
);


// --- UI Components ---

const Header = () => {
  return (
    <header className="app-header no-print">
      <div className="title-group">
        <Zap size={32} color="var(--color-primary)" />
        <h1>AI-Driven Threat Modeling Platform</h1>
      </div>
      <div style={{color: 'var(--color-text-muted)'}}>Continuous Security for Modern SDLC</div>
    </header>
  );
};

const FileUploader = ({ onFilesAdded }) => {
  const [files, setFiles] = useState([]);

  const handleFileChange = (e) => {
    const newFiles = Array.from(e.target.files).map(file => ({
      name: file.name,
      size: file.size,
      type: file.type,
    }));
    
    newFiles.forEach((fileInfo, index) => {
        const reader = new FileReader();
        reader.onload = (event) => {
            fileInfo.content = event.target.result;
            if (index === newFiles.length - 1) {
                const allFiles = [...files, ...newFiles];
                setFiles(allFiles);
                onFilesAdded(allFiles);
            }
        };
        reader.readAsText(e.target.files[index]);
    });
  };
  
  const removeFile = (fileName) => {
      const updatedFiles = files.filter(f => f.name !== fileName);
      setFiles(updatedFiles);
      onFilesAdded(updatedFiles);
  }

  return (
    <div className="card">
      <div className="dropzone">
        <Upload size={48} color="var(--color-text-muted)" style={{marginBottom: '1rem'}}/>
        <label htmlFor="file-upload" style={{cursor: 'pointer'}}>
          <span className="btn">Upload Project Artifacts</span>
        </label>
        <input id="file-upload" type="file" multiple style={{display: 'none'}} onChange={handleFileChange} />
        <p style={{color: 'var(--color-text-muted)', marginTop: '1rem', marginBottom: 0}}>Drag & drop or click to upload</p>
        <p style={{color: 'var(--color-border)', fontSize: '0.8rem'}}>Diagrams, IaC files, User Stories, Source Code...</p>
      </div>
      {files.length > 0 && (
        <ul className="file-list">
          <h4>Uploaded Files:</h4>
          {files.map((file, index) => (
            <li key={index} className="file-item">
              <div style={{display: 'flex', alignItems: 'center', gap: '0.75rem'}}>
                <FileText color="var(--color-text-muted)" />
                <span>{file.name}</span>
              </div>
              <div style={{display: 'flex', alignItems: 'center', gap: '1rem'}}>
                <span style={{fontSize: '0.8rem', color: 'var(--color-text-muted)'}}>{(file.size / 1024).toFixed(2)} KB</span>
                 <button onClick={() => removeFile(file.name)} style={{background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--color-text-muted)'}}>
                      <X size={16} />
                 </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

const AnalysisInProgress = ({ projectName, onCancel }) => (
    <div style={{textAlign: 'center', padding: '3rem 0'}}>
        <div className="spinner"><Cpu size={64}/></div>
        <h2 style={{marginTop: '1.5rem'}}>Analyzing {projectName}...</h2>
        <p style={{color: 'var(--color-text-muted)'}}>The AI engine is identifying assets, data flows, and potential threats.</p>
        <div className="progress-bar"><div className="progress-bar-inner" /></div>
        <button onClick={onCancel} className="btn btn-danger" style={{marginTop: '2rem'}}>
            Cancel Analysis
        </button>
    </div>
);

const ThreatItem = ({ threat, onSelect }) => {
    const severityClass = `severity-${threat.severity.toLowerCase()}`;
    return (
        <tr>
            <td><span className={`severity-badge ${severityClass}`}>{threat.severity}</span></td>
            <td>{threat.category}</td>
            <td style={{color: 'var(--color-text-muted)'}}>{threat.threat}</td>
            <td>{threat.component}</td>
            <td style={{textAlign: 'right'}} className="no-print">
                <button onClick={() => onSelect(threat)} className="btn" style={{padding: '0.5rem 1rem', fontSize: '0.9rem'}}>
                    View Mitigation
                </button>
            </td>
        </tr>
    );
}

const MitigationModal = ({ threat, onClose }) => {
    if (!threat) return null;
    
    return (
        <div className="modal-backdrop">
            <div className="modal-content">
                <div className="modal-header">
                    <h5><AlertTriangle color="var(--color-warning)"/> Mitigation Details</h5>
                    <button onClick={onClose} style={{background:'none', border:'none', color: 'var(--color-text-muted)', cursor:'pointer'}}><X/></button>
                </div>
                <div className="modal-body">
                    <div>
                        <h6>Identified Threat</h6>
                        <p style={{color: 'var(--color-text-muted)'}}>{threat.threat}</p>
                    </div>
                    <div className="info-grid">
                        <div className="card info-card"><span style={{fontSize:'0.8rem', color:'var(--color-text-muted)'}}>Severity</span><p style={{fontWeight:'bold', margin:0}}>{threat.severity}</p></div>
                        <div className="card info-card"><span style={{fontSize:'0.8rem', color:'var(--color-text-muted)'}}>STRIDE Category</span><p style={{fontWeight:'bold', margin:0}}>{threat.category}</p></div>
                        <div className="card info-card"><span style={{fontSize:'0.8rem', color:'var(--color-text-muted)'}}>Affected Component</span><p style={{fontWeight:'bold', margin:0}}>{threat.component}</p></div>
                    </div>
                    <div>
                        <h6 style={{display:'flex', alignItems:'center', gap:'0.5rem'}}><Lightbulb color="var(--color-success)"/> Security Recommendation</h6>
                        <p style={{color: 'var(--color-text-muted)', backgroundColor: 'var(--color-bg)', padding: '1rem', borderRadius: '6px', border: `1px solid var(--color-border)`}}>{threat.mitigation}</p>
                    </div>
                    <div>
                        <h6 style={{display:'flex', alignItems:'center', gap:'0.5rem'}}><Code color="var(--color-primary)"/> Example Code Snippet</h6>
                        <pre className="code-block"><code>{threat.codeSnippet}</code></pre>
                    </div>
                </div>
                <div className="modal-footer">
                    <button onClick={onClose} className="btn">Close</button>
                </div>
            </div>
        </div>
    );
};

const DataFlowDiagram = ({ nodes = [], edges = [] }) => {
    const positions = useMemo(() => {
        const pos = {};
        const numNodes = nodes.length;
        if (numNodes === 0) return {};
        
        const center = { x: 250, y: 175 };
        const radius = 120;

        nodes.forEach((node, i) => {
            const angle = (i / numNodes) * 2 * Math.PI - Math.PI / 2;
            pos[node.id] = {
                x: center.x + radius * Math.cos(angle),
                y: center.y + radius * Math.sin(angle),
            };
        });
        return pos;
    }, [nodes]);

    if (nodes.length === 0) {
        return (
            <div className="diagram-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <p style={{ color: 'var(--color-text-muted)', fontSize: '0.9rem' }}>No architectural assets identified to draw a diagram.</p>
            </div>
        );
    }

    const nodeWidth = 150;
    const nodeHeight = 40;

    return (
        <div className="diagram-container">
            <svg width="100%" height="100%" viewBox="0 0 500 350">
                <defs>
                    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="8" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="var(--color-medium-blue)" />
                    </marker>
                </defs>

                {/* Edges */}
                {edges.map((edge, i) => {
                    const fromPos = positions[edge.from];
                    const toPos = positions[edge.to];
                    if (!fromPos || !toPos) return null;
                    
                    const midX = (fromPos.x + toPos.x) / 2;
                    const midY = (fromPos.y + toPos.y) / 2;

                    return (
                        <g key={`edge-${i}`}>
                            <path
                                d={`M ${fromPos.x} ${fromPos.y} L ${toPos.x} ${toPos.y}`}
                                className="diagram-edge"
                            />
                            <text x={midX} y={midY - 5} className="diagram-edge-label">
                                {edge.label}
                            </text>
                        </g>
                    );
                })}
                
                {/* Nodes */}
                {nodes.map(node => {
                    const pos = positions[node.id];
                    if (!pos) return null;
                    return (
                       <g key={node.id} transform={`translate(${pos.x - nodeWidth/2}, ${pos.y - nodeHeight/2})`}>
                           <rect 
                             width={nodeWidth}
                             height={nodeHeight}
                             rx="6"
                             className="diagram-node-rect"
                           />
                           <text x={nodeWidth/2} y={nodeHeight/2} className="diagram-node-text">
                               {node.label}
                           </text>
                       </g>
                    );
                })}
            </svg>
        </div>
    );
};


const ResultsDashboard = ({ projectName, analysis, onReset }) => {
    const [selectedThreat, setSelectedThreat] = useState(null);
    const { assets, dataFlows, threats, diagramData } = analysis;

    const handleSavePdf = () => {
        window.print();
    };

    const severityCounts = useMemo(() => {
        return threats.reduce((acc, threat) => {
            acc[threat.severity] = (acc[threat.severity] || 0) + 1;
            return acc;
        }, {});
    }, [threats]);

    const stats = [
        { name: 'Identified Threats', value: threats.length, icon: AlertTriangle, color: 'var(--color-warning)' },
        { name: 'High-Risk Threats', value: (severityCounts['High'] || 0) + (severityCounts['Critical'] || 0), icon: Zap, color: 'var(--color-danger)' },
        { name: 'Identified Assets', value: assets.size, icon: Server, color: 'var(--color-primary)' },
        { name: 'Data Flows', value: dataFlows.length, icon: ArrowRight, color: 'var(--color-success)' },
    ];
    
    return (
        <div className="results-printable-area" style={{padding: '2rem'}}>
            <div className="dashboard-header">
                <div>
                    <h2>Threat Model for: {projectName}</h2>
                    <p style={{color: 'var(--color-text-muted)'}}>Analysis complete. Review the threats below.</p>
                </div>
                 <div className="dashboard-actions no-print">
                     <button onClick={onReset} className="btn btn-secondary">Start New Analysis</button>
                     <button onClick={handleSavePdf} className="btn"><Download size={20}/> Save as PDF</button>
                 </div>
            </div>

            <div className="stats-grid">
                {stats.map(stat => (
                    <div key={stat.name} className="card" style={{display:'flex', alignItems:'center', gap:'1rem'}}>
                        <div className="stat-card-icon" style={{color: stat.color}}>
                            <stat.icon size={24} />
                        </div>
                        <div>
                            <p style={{fontSize:'1.75rem', fontWeight:'bold', margin:0}}>{stat.value}</p>
                            <p style={{color: 'var(--color-text-muted)', margin:0, fontSize: '0.9rem'}}>{stat.name}</p>
                        </div>
                    </div>
                ))}
            </div>
            
            <div className="main-grid">
               <div className="card">
                    <h5>Architecture & Data Flow Diagram</h5>
                    <DataFlowDiagram nodes={diagramData.nodes} edges={diagramData.edges} />
               </div>
               <div className="card">
                   <h5>Key Assets Identified</h5>
                   <ul style={{listStyle:'none', padding:0, margin: '1rem 0 0', display:'flex', flexDirection:'column', gap:'0.75rem'}}>
                        {Array.from(assets).map(asset => (
                            <li key={asset} style={{display:'flex', alignItems:'center', gap:'0.5rem'}}>
                                <CheckCircle color="var(--color-success)" size={20}/>
                                <span>{asset}</span>
                            </li>
                        ))}
                   </ul>
               </div>
            </div>

             <div className="card" style={{marginTop:'2rem', padding: '0'}}>
                <h5 style={{padding:'1.5rem 1.5rem 0'}}>Prioritized Threats (STRIDE Framework)</h5>
                <div style={{overflowX:'auto'}}>
                  <table className="threat-table">
                      <thead>
                          <tr>
                              <th>Severity</th>
                              <th>Category</th>
                              <th>Threat Description</th>
                              <th>Component</th>
                              <th className="no-print">Action</th>
                          </tr>
                      </thead>
                      <tbody>
                          {threats.sort((a,b) => {
                              const order = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
                              return order[b.severity] - order[a.severity];
                          }).map(threat => (
                              <ThreatItem key={threat.id} threat={threat} onSelect={setSelectedThreat}/>
                          ))}
                      </tbody>
                  </table>
                </div>
            </div>

            {selectedThreat && <MitigationModal threat={selectedThreat} onClose={() => setSelectedThreat(null)} />}
        </div>
    );
};

// --- Main App Component ---

function App() {
  const [projectName, setProjectName] = useState('');
  const [files, setFiles] = useState([]);
  const [view, setView] = useState('form');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [formError, setFormError] = useState('');
  const abortControllerRef = useRef(null);

  const handleStartAnalysis = async () => {
    if (!projectName || files.length === 0) {
      setFormError('Please provide a project name and upload at least one artifact.');
      return;
    }
    setFormError('');
    setError(null);
    setView('analyzing');
    
    abortControllerRef.current = new AbortController();
    
    try {
        const result = await aiEngine.analyzeArtifacts(files, { signal: abortControllerRef.current.signal });
        setAnalysisResult(result);
        setView('results');
    } catch (e) {
        if (e.name === 'AbortError') {
          console.log('Analysis was canceled by the user.');
          // handleReset is called from the cancel handler to give immediate feedback
        } else {
          console.error("Analysis failed:", e);
          setError("Failed to analyze artifacts. The AI model may be unavailable or the input is invalid. Please check your console and try again.");
          setView('form');
        }
    }
  };

  const handleCancelAnalysis = () => {
      if (abortControllerRef.current) {
          abortControllerRef.current.abort();
      }
      handleReset(); // Reset the state immediately for better UX
  };

  const handleReset = () => {
      setProjectName('');
      setFiles([]);
      setAnalysisResult(null);
      setError(null);
      setFormError('');
      setView('form');
  }
  
  const renderContent = () => {
    switch(view) {
        case 'analyzing':
            return <AnalysisInProgress projectName={projectName} onCancel={handleCancelAnalysis} />;
        case 'results':
            return <ResultsDashboard projectName={projectName} analysis={analysisResult} onReset={handleReset}/>;
        case 'form':
        default:
            return (
                <div className="form-container">
                    <div style={{textAlign: 'center', marginBottom: '2rem'}}>
                        <h2>Create a New Threat Model</h2>
                        <p style={{color: 'var(--color-text-muted)'}}>Provide your project's details and artifacts to generate a comprehensive threat model.</p>
                    </div>

                    {error && <div className="alert-box alert-danger">{error}</div>}
                    {formError && <div className="alert-box alert-warning">{formError}</div>}
                    
                    <div style={{display:'flex', flexDirection:'column', gap:'1.5rem'}}>
                      <div>
                          <label htmlFor="project-name" style={{marginBottom:'0.5rem', display:'block', fontWeight: 600}}>Project Name</label>
                          <input
                              type="text"
                              id="project-name"
                              value={projectName}
                              onChange={(e) => setProjectName(e.target.value)}
                              placeholder="e.g., E-commerce Platform Q4"
                              className="form-input"
                          />
                      </div>
                      
                      <FileUploader onFilesAdded={setFiles} />
                    </div>
                    
                    <div style={{display:'flex', justifyContent:'flex-end', marginTop:'2rem', paddingTop:'2rem', borderTop: `1px solid var(--color-border)`}}>
                        <button onClick={handleStartAnalysis} disabled={!projectName || files.length === 0} className="btn">
                            <Cpu size={20} />
                            <span>Start AI Analysis</span>
                        </button>
                    </div>
                </div>
            )
    }
  }

  return (
    <>
      <Styles />
      <Header />
      <main>
          {renderContent()}
      </main>
      <footer className="footer no-print">
          <h6 style={{fontWeight:'bold', color:'var(--color-text)', marginBottom:'0.5rem'}}>Engineered with Responsible AI Principles</h6>
          <p style={{margin:0}}>Security, Fairness, Privacy & Legal Compliance are at the core of our design.</p>
          <p style={{marginTop:'1.5rem'}}>&copy; 2025 AI Threat Modeling Platform. All rights reserved.</p>
      </footer>
    </>
  );
}

export default App;
