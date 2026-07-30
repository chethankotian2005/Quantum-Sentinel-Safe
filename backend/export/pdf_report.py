import os
from jinja2 import Template
import logging
from datetime import datetime

try:
    from xhtml2pdf import pisa
    XHTML2PDF_AVAILABLE = True
except (ImportError, OSError):
    XHTML2PDF_AVAILABLE = False
    logging.warning("xhtml2pdf missing. PDF generation will fallback to HTML.")
from models.schemas import ScanResult

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Quantum Risk Report - {{ scan.scan_id }}</title>
    <style>
        @page {
            size: A4;
            margin: 2cm;
            @frame header {
                -pdf-frame-content: header_content;
                top: 1cm;
                margin-left: 2cm;
                margin-right: 2cm;
                height: 1cm;
            }
            @frame footer {
                -pdf-frame-content: footer_content;
                bottom: 1cm;
                margin-left: 2cm;
                margin-right: 2cm;
                height: 1cm;
            }
        }
        body { font-family: "Helvetica", "Arial", sans-serif; color: #222; background-color: #fff; font-size: 11pt; }
        h1, h2, h3, h4 { color: #1a252f; font-family: "Helvetica Neue", "Arial", sans-serif; }
        
        /* Cover Page */
        .cover { text-align: center; margin-top: 150px; }
        .cover h1 { font-size: 36pt; margin-bottom: 20px; color: #2c3e50; }
        .cover h2 { font-size: 24pt; color: #7f8c8d; font-weight: normal; }
        .cover-details { margin-top: 100px; font-size: 14pt; color: #34495e; text-align: left; width: 60%; margin-left: auto; margin-right: auto; }
        .cover-details th { text-align: right; padding-right: 20px; color: #7f8c8d; width: 50%; }
        .cover-details td { padding-left: 20px; font-weight: bold; border: none; }
        .cover-details tr:nth-child(even) { background-color: transparent; }
        
        .page-break { pdf-pagebreak-before: always; }
        
        /* Badges */
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.9em; text-align: center; }
        .badge-Critical { background-color: #c0392b; color: white; }
        .badge-High { background-color: #e67e22; color: white; }
        .badge-Medium { background-color: #f1c40f; color: #333; }
        .badge-Low { background-color: #3498db; color: white; }

        .grade-badge { font-size: 36px; padding: 15px 30px; border-radius: 8px; display: inline-block; font-weight: bold; color: white; margin-bottom: 15px;}
        .grade-A { background-color: #27ae60; }
        .grade-B { background-color: #2ecc71; }
        .grade-C { background-color: #f1c40f; color: #333;}
        .grade-D { background-color: #e67e22; }
        .grade-F { background-color: #c0392b; }

        /* Tables */
        table { width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 25px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }
        th { background-color: #f8f9fa; color: #2c3e50; font-weight: bold; }
        tr:nth-child(even) { background-color: #fcfcfc; }
        
        /* Finding Block */
        .finding-block { border: 1px solid #e0e0e0; border-radius: 6px; padding: 15px; margin-bottom: 20px; page-break-inside: avoid; }
        .finding-header { display: block; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 10px; }
        .finding-title { font-size: 14pt; font-weight: bold; color: #2c3e50; display: inline-block;}
        .finding-badge { float: right; }
        
        /* Utility */
        .text-right { text-align: right; }
        .header, .footer { font-size: 9pt; color: #7f8c8d; }
        .footer { text-align: center; }
        .section-header { border-bottom: 2px solid #2c3e50; padding-bottom: 5px; margin-top: 30px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div id="header_content" class="header">
        QuantumSafe Sentinel | Confidential Security Report
    </div>
    <div id="footer_content" class="footer">
        Page <pdf:pagenumber> of <pdf:pagecount> | Generated {{ scan.timestamp or generated_date }}
    </div>

    <!-- COVER PAGE -->
    <div class="cover">
        <h1>Quantum Risk Assessment</h1>
        <h2>Executive Security Report</h2>
        
        <table class="cover-details">
            <tr><th>Scan ID:</th><td>{{ scan.scan_id }}</td></tr>
            <tr><th>Scan Target:</th><td>{{ scan.target_id or 'N/A' }}</td></tr>
            <tr><th>Date:</th><td>{{ scan.timestamp or generated_date }}</td></tr>
        </table>
    </div>

    <div class="page-break"></div>

    <!-- EXECUTIVE SUMMARY -->
    <h2 class="section-header">Executive Summary</h2>
    {% if scan.risk_score %}
    <div>
        <div class="grade-badge grade-{{ scan.risk_score.grade }}">
            Grade: {{ scan.risk_score.grade }}
        </div>
        <p style="font-size: 14pt; margin-top: 5px;"><strong>Overall Score:</strong> {{ scan.risk_score.score }} / 100</p>
        <div style="margin-top: 20px;">
            <strong>Findings Summary:</strong><br><br>
            <span class="badge badge-Critical">{{ scan.risk_score.critical_count }} Critical</span> &nbsp;
            <span class="badge badge-High">{{ scan.risk_score.high_count }} High</span> &nbsp;
            <span class="badge badge-Medium">{{ scan.risk_score.medium_count }} Medium</span> &nbsp;
            <span class="badge badge-Low">{{ scan.risk_score.low_count }} Low</span>
        </div>
    </div>
    {% endif %}
    
    {% if scan.impact %}
    <h3 style="margin-top: 40px;">Migration Impact Estimate</h3>
    <table>
        <tr><th>Estimated Storage Bloat</th><td>{{ scan.impact.estimated_additional_storage_mb }} MB/day</td></tr>
        <tr><th>Handshake Latency Penalty</th><td>+{{ scan.impact.estimated_handshake_overhead_ms }} ms per connection</td></tr>
        <tr><th>Bandwidth Increase</th><td>{{ scan.impact.estimated_additional_bandwidth_pct }}%</td></tr>
    </table>
    <p><i>Note: {{ scan.impact.notes }}</i></p>
    {% endif %}

    <div class="page-break"></div>

    <!-- DETAILED FINDINGS -->
    <h2 class="section-header">Detailed Findings & Analysis</h2>
    {% for f in scan.findings %}
    {% set rec = scan.recommendations[loop.index0] %}
    <div class="finding-block">
        <div class="finding-header">
            <span class="finding-title">{{ f.algorithm }} {% if f.key_size %}({{ f.key_size }} bits){% else %}(Unknown bits){% endif %}</span>
            <span class="badge badge-{{ f.risk_score.value }} finding-badge">{{ f.risk_score.value }}</span>
        </div>
        
        <p><strong>Source:</strong> {{ f.file or f.hostname or 'Unknown' }}{% if f.line %} (Line {{ f.line }}){% endif %}</p>
        <p><strong>Context & Usage:</strong> {{ f.context.value }} / {{ f.usage_type.value }}</p>

        {% if not f.is_actionable %}
        <div style="margin-top: 10px; padding: 10px; background-color: #fff3cd; border-left: 4px solid #ffecb5; color: #856404;">
            <strong>Informational:</strong> This CA-issued intermediate/root certificate is part of the chain but is not typically directly controlled by the target organization. It is included for visibility.
        </div>
        {% endif %}
        
        <div style="margin-top: 10px; padding: 10px; background-color: #f9f9f9; border-left: 4px solid #3498db;">
            <p style="margin-top: 0; margin-bottom: 5px;"><strong>Stage 1 (Hybrid Mode):</strong> <span style="font-family: monospace;">{{ rec.stage_1_hybrid }}</span></p>
            <p style="margin-top: 0; margin-bottom: 10px; font-size: 0.9em; color: #555;"><i>{{ rec.stage_1_rationale }}</i></p>
            <p style="margin-top: 0; margin-bottom: 0;"><strong>Stage 2 (Pure PQC):</strong> <span style="font-family: monospace;">{{ rec.stage_2_pqc }}</span></p>
        </div>
        
        {% if f.mosca_result %}
        <div style="margin-top:15px; border-top:1px dashed #ccc; padding-top:10px;">
            <h4 style="margin-bottom: 5px;">Mosca's Inequality Theorem</h4>
            <p style="margin-top: 5px; margin-bottom: 5px;"><strong>Verdict:</strong> <span style="color: {% if 'At Risk' in f.mosca_result.verdict %}#c0392b{% else %}#27ae60{% endif %}; font-weight: bold;">{{ f.mosca_result.verdict }}</span></p>
            <p style="margin-top: 5px; margin-bottom: 5px;"><i>X (Data Shelf Life: {{ f.mosca_result.x }}y) + Y (Migration Time: {{ f.mosca_result.y }}y) = {{ f.mosca_result.sum_xy }} years vs Z (Threat Horizon: {{ f.mosca_result.z }}y).</i></p>
            <p style="margin-top: 5px; margin-bottom: 5px;"><strong>Margin:</strong> {{ f.mosca_result.margin_years }} years.</p>
            <p style="margin-top: 5px; font-size: 0.95em;">{{ f.mosca_result.explanation }}</p>
        </div>
        {% endif %}
        
        {% if f.quantum_attack_cost %}
        <div style="margin-top:15px; border-top:1px dashed #ccc; padding-top:10px;">
            <h4 style="margin-bottom: 5px;">Quantum Attack Cost (QAC) Breakdown</h4>
            <table style="margin-top: 10px; margin-bottom: 10px;">
                <tr>
                    <th style="width: 33%;">Logical Qubits</th>
                    <th style="width: 33%;">Physical Qubits</th>
                    <th style="width: 33%;">Hardware Gap</th>
                </tr>
                <tr>
                    <td>{{ "{:,}".format(f.quantum_attack_cost.idealized_logical_qubits) }}</td>
                    <td>{{ "{:,}".format(f.quantum_attack_cost.realistic_physical_qubits_estimate) }}</td>
                    <td>{{ "{:,.1f}".format(f.quantum_attack_cost.gap_factor) }}x</td>
                </tr>
            </table>
            <p style="margin-top: 5px; font-size: 0.9em; color: #555;"><i>{{ f.quantum_attack_cost.comparison_to_current_hardware }}</i></p>
        </div>
        {% endif %}
    </div>
    {% endfor %}

    {% if framework_violations %}
    <div class="page-break"></div>
    <h2 class="section-header">Regulatory Exposure</h2>
    <p>The following frameworks and mandates are actively violated by findings in this scan:</p>
    
    {% for fw_name, fw_data in framework_violations.items() %}
    <div class="finding-block">
        <h3>{{ fw_name }}</h3>
        <p><strong>Requirement:</strong> {{ fw_data.summary }}</p>
        <p><strong>Deadline:</strong> <span style="color:#c0392b; font-weight:bold;">{{ fw_data.deadline }}</span></p>
        <p><small>Source: <a href="{{ fw_data.source_link }}">{{ fw_data.source_link }}</a></small></p>
        
        <h4 style="margin-top: 15px;">Violating Assets ({{ fw_data.findings|length }} findings):</h4>
        <ul>
            {% for f in fw_data.findings %}
            <li style="margin-bottom: 5px;">{{ f.file or f.hostname or 'Unknown Asset' }}{% if f.line %} (Line {{ f.line }}){% endif %} - <strong>{{ f.algorithm }}</strong> <span class="badge badge-{{ f.risk_score.value }}" style="font-size: 0.8em;">{{ f.risk_score.value }}</span></li>
            {% endfor %}
        </ul>
    </div>
    {% endfor %}
    {% endif %}
</body>
</html>
"""

def generate_pdf_report(scan_result: ScanResult, filepath: str) -> None:
    """
    Renders a PDF report displaying Executive Grade, Migration Impact, etc.
    Uses xhtml2pdf to avoid GTK3 dependencies on Windows.
    """
    
    framework_violations = {}
    for f in scan_result.findings:
        if f.compliance_flags:
            for flag in f.compliance_flags:
                if flag.framework_name not in framework_violations:
                    framework_violations[flag.framework_name] = {
                        "summary": flag.summary,
                        "deadline": flag.deadline,
                        "source_link": flag.source_link,
                        "findings": []
                    }
                framework_violations[flag.framework_name]["findings"].append(f)

    # Ensure we have a generation date
    generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        scan=scan_result, 
        framework_violations=framework_violations,
        generated_date=generated_date
    )
    
    if XHTML2PDF_AVAILABLE:
        with open(filepath, "w+b") as result_file:
            pisa_status = pisa.CreatePDF(html_content, dest=result_file)
            if pisa_status.err:
                logging.error(f"Error generating PDF: {pisa_status.err}")
                # Fallback on err
                html_filepath = filepath.replace(".pdf", ".html")
                with open(html_filepath, "w", encoding="utf-8") as f:
                    f.write(html_content)
    else:
        # Fallback to HTML if PDF engine isn't available natively
        html_filepath = filepath.replace(".pdf", ".html")
        with open(html_filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"xhtml2pdf missing. Generated HTML fallback at: {html_filepath}")
