import { jsPDF } from 'jspdf';
import 'jspdf-autotable';

/** 
 * Export to CSV 
 */
export const downloadCSV = (data) => {
  const attackers = (data?.classified_ips || []).filter(r => r.attack_type !== 'Normal');
  
  if (!attackers.length) {
    alert("No threat data available to export.");
    return;
  }

  const headers = ['IP Address', 'Attack Type', 'Severity', 'Confidence (%)', 'Failed Attempts', 'Request Rate (/sec)', 'Unique Usernames'];
  const rows = attackers.map(r => [
    r.ip,
    `"${r.attack_type}"`,
    `"${r.severity}"`,
    r.confidence,
    r.failed_attempts,
    r.request_rate,
    r.unique_usernames
  ]);

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', `logcentric_threat_report_${new Date().toISOString().split('T')[0]}.csv`);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

/** 
 * Helper: Sanitize text for PDF (Removes weird encoding artifacts)
 */
const sanitizeForPDF = (str) => {
  if (!str) return "";
  return str
    .replace(/[^\x00-\x7F]/g, " ") // Clean non-ASCII artifacts
    .replace(/\[\s+\]/g, "[ ]")
    .replace(/\r/g, "");
};

/** 
 * Helper: Render a technical monospaced section with page splitting
 * @param {jsPDF} doc - jsPDF instance
 * @param {string} title - Section header
 * @param {string} content - Raw multi-line text
 * @param {number[]} headerColor - RGB array
 * @param {object} config - Margins and width
 */
const renderTechnicalSection = (doc, title, content, headerColor, config) => {
  if (!content) return;
  
  const { leftMargin, contentWidth } = config;

  doc.addPage();
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(15, 23, 42); // Slate 900
  doc.text(title, leftMargin, 20);
  
  doc.setDrawColor(headerColor[0], headerColor[1], headerColor[2]);
  doc.setLineWidth(0.8);
  doc.line(leftMargin, 22, leftMargin + (doc.getTextWidth(title) + 5), 22);
  
  doc.setFont('courier', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(30, 41, 59);
  
  const sanitized = sanitizeForPDF(content);
  const lines = sanitized.split('\n');
  let cursorY = 35;

  lines.forEach(line => {
    const wrapped = doc.splitTextToSize(line, contentWidth);
    
    if (cursorY + (wrapped.length * 4.5) > 280) {
      doc.addPage();
      cursorY = 25;
    }
    
    doc.text(wrapped, leftMargin, cursorY);
    cursorY += (wrapped.length * 4.5);
  });
};

/** 
 * Export to PDF 
 * Comprehensive Intelligence Report implementation
 */
export const downloadPDF = (data) => {
  const doc = new jsPDF({
    orientation: 'p',
    unit: 'mm',
    format: 'a4',
  });

  const timestamp = new Date().toLocaleString();
  const attackers = (data?.classified_ips || []).filter(r => r.attack_type !== 'Normal');
  const config = { leftMargin: 20, rightBuffer: 10, pageWidth: 210 };
  config.contentWidth = config.pageWidth - (config.leftMargin * 2) - config.rightBuffer;

  // 1. Branding & Header Page 1
  doc.setFillColor(15, 23, 42); // Slate 900
  doc.rect(0, 0, config.pageWidth, 45, 'F');
  
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(24);
  doc.text('LOGCENTRIC', config.leftMargin, 22);
  
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.text('Security Intelligence & Threat Analysis Report', config.leftMargin, 32);
  
  doc.setFontSize(8);
  doc.setTextColor(200, 200, 200);
  doc.text(`Generated: ${timestamp}`, config.pageWidth - config.leftMargin, 32, { align: 'right' });

  // 2. Executive Summary
  let cursorY = 60;
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.text('Executive Summary', config.leftMargin, cursorY);
  cursorY += 2;
  doc.setDrawColor(56, 189, 248); // Cyan 400
  doc.setLineWidth(0.8);
  doc.line(config.leftMargin, cursorY, config.leftMargin + 48, cursorY);
  cursorY += 12;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(51, 65, 85); 
  
  const summaryItems = [
    { label: 'Analysis State:', value: attackers.length > 0 ? 'ACTIVE THREATS IDENTIFIED' : 'NO THREATS DETECTED' },
    { label: 'Total Logs Processed:', value: data.total_events.toLocaleString() },
    { label: 'Identified Actors:', value: `${attackers.length} unique IPs` },
    { label: 'Critical Severity:', value: `${attackers.filter(r => r.severity === 'CRITICAL').length} incidents` },
    { label: 'Successful Traffic:', value: data.successes.toLocaleString() }
  ];

  summaryItems.forEach(item => {
    doc.setFont('helvetica', 'bold');
    doc.text(item.label, config.leftMargin, cursorY);
    doc.setFont('helvetica', 'normal');
    doc.text(item.value, config.leftMargin + 55, cursorY);
    cursorY += 8;
  });

  cursorY += 10;

  // 3. Threat Analysis Narrative (Page 1 flow)
  if (data.threat_narrative) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(15);
    doc.setTextColor(15, 23, 42);
    doc.text('Threat Analysis Summary', config.leftMargin, cursorY);
    cursorY += 2;
    doc.line(config.leftMargin, cursorY, config.leftMargin + 62, cursorY);
    cursorY += 10;
    
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10.5);
    doc.setTextColor(71, 85, 105); 
    
    const sanitizedNarrative = sanitizeForPDF(data.threat_narrative);
    const splitNarrative = doc.splitTextToSize(sanitizedNarrative, config.contentWidth);
    
    splitNarrative.forEach(line => {
      if (cursorY > 275) {
        doc.addPage();
        cursorY = 25;
      }
      doc.text(line, config.leftMargin, cursorY);
      cursorY += 6.5; 
    });
  }

  // 4. Detailed Attacker Table
  if (attackers.length > 0) {
    doc.addPage();
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(15);
    doc.setTextColor(15, 23, 42);
    doc.text('Verified Threat Actors', config.leftMargin, 20);
    
    const tableHeaders = [['IP Address', 'Pattern Classification', 'Risk Level', 'Confidence', 'Failures', 'Targets']];
    const tableData = attackers.map(r => [
      r.ip,
      r.attack_type,
      r.severity,
      `${r.confidence}%`,
      r.failed_attempts,
      r.unique_usernames
    ]);

    doc.autoTable({
      startY: 28,
      margin: { left: config.leftMargin, right: config.leftMargin },
      head: tableHeaders,
      body: tableData,
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: 255, fontSize: 9, fontStyle: 'bold', halign: 'center' },
      styles: { fontSize: 8, cellPadding: 4, valign: 'middle', font: 'helvetica' },
      columnStyles: { 0: { fontStyle: 'bold', textColor: [14, 165, 233] } },
      alternateRowStyles: { fillColor: [248, 250, 252] }
    });
  }

  /** Technical Appendices (Each on a new page) **/
  
  // 5. SOC Report
  renderTechnicalSection(doc, 'SOC Mitigation Recommendations', data.soc_report, [244, 63, 94], config); // Rose 500
  
  // 6. Firewall Rules
  renderTechnicalSection(doc, 'Network Hardening Strategy', data.firewall_rules, [56, 189, 248], config); // Sky 500
  
  // 7. Alert Emails
  renderTechnicalSection(doc, 'Incident Communication Assets', data.alert_emails, [245, 158, 11], config); // Amber 500

  // Final Pass: Footer on all pages
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184); 
    doc.text(`LogCentric Security Intelligence Portfolio · Generated: ${fileDate()} · Page ${i} of ${pageCount}`, config.pageWidth / 2, 287, { align: 'center' });
  }

  function fileDate() { return new Date().toISOString().split('T')[0]; }
  doc.save(`logcentric_security_full_report_${new Date().getTime()}.pdf`);
};
