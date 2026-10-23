const fs = require('fs');
let styles = fs.readFileSync('styles.css', 'utf8');

// Replace Light Theme Variables
const lightVars = `
  /* PREMIUM LIGHT TOKENS */
  --bg: #F0F4F8; /* subtle cool gray-blue background */
  --surface: #FFFFFF;
  --surface-soft: #F8FAFC;
  
  --border: #E2E8F0;
  --border-soft: #F1F5F9;
  
  --ink: #1E293B;
  --ink-strong: #0F172A;
  --ink-soft: #475569;
  --muted: #64748B;
  --muted-light: #94A3B8;
  
  --accent: #2563EB;
  --accent-soft: rgba(37, 99, 235, 0.1);
  --accent-hover: #1D4ED8;
  
  --critical: #DC2626;
  --critical-bg: #FEF2F2;
  --high: #EA580C;
  --high-bg: #FFF7ED;
  --medium: #D97706;
  --medium-bg: #FFFBEB;
  --low: #16A34A; /* wait, script.js uses --pass for low? */
  --pass: #16A34A;
  --pass-bg: #F0FDF4;
  --info: #64748B;
  --info-bg: #F1F5F9;
  
  --sidebar-bg: linear-gradient(180deg, #0A1121 0%, #0F192C 100%);
  --sidebar-border: rgba(255, 255, 255, 0.06);
  --sidebar-text: #94A3B8;
  --sidebar-text-active: #FFFFFF;
  --sidebar-text-hover: #E2E8F0;
  
  --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --shadow-panel: 0 4px 6px -1px rgba(0, 0, 0, 0.03), 0 2px 4px -1px rgba(0, 0, 0, 0.02);
  --shadow-hover: 0 10px 15px -3px rgba(0, 0, 0, 0.06), 0 4px 6px -2px rgba(0, 0, 0, 0.04);
  
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
`;

// Replace Dark Theme Variables
const darkVars = `
  /* PREMIUM DARK TOKENS */
  --bg: #090E17; /* deep navy gradient base */
  --surface: #111827;
  --surface-soft: #162032;
  
  --border: #1F2937;
  --border-soft: #374151;
  
  --ink: #F9FAFB;
  --ink-strong: #FFFFFF;
  --ink-soft: #D1D5DB;
  --muted: #9CA3AF;
  --muted-light: #6B7280;
  
  --accent: #3B82F6;
  --accent-soft: rgba(59, 130, 246, 0.15);
  --accent-hover: #60A5FA;
  
  --critical: #EF4444;
  --critical-bg: rgba(239, 68, 68, 0.1);
  --high: #F97316;
  --high-bg: rgba(249, 115, 22, 0.1);
  --medium: #F59E0B;
  --medium-bg: rgba(245, 158, 11, 0.1);
  --pass: #22C55E;
  --pass-bg: rgba(34, 197, 94, 0.1);
  --info: #9CA3AF;
  --info-bg: rgba(156, 163, 175, 0.1);
  
  --sidebar-bg: linear-gradient(180deg, #05080F 0%, #090E17 100%);
  --sidebar-border: rgba(255, 255, 255, 0.04);
  
  --shadow-panel: 0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
  --shadow-hover: 0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -2px rgba(0, 0, 0, 0.3);
`;

styles = styles.replace(/:root\s*\{[^}]+\}/, `:root {\n${lightVars}\n}`);
styles = styles.replace(/body\.dark-mode\s*\{[^}]+\}/, `body.dark-mode {\n${darkVars}\n}`);

fs.writeFileSync('styles.css', styles);
