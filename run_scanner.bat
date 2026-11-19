@echo off
echo ===================================================
echo Starting VulnEdge Scanner (Backend + Frontend)...
echo ===================================================

:: 1. पायथन बैकएंड सर्वर को नए टर्मिनल में स्टार्ट करें
start cmd /k "python scanner.py"

:: 2. रिएक्ट फ्रंटएंड को इसी टर्मिनल में स्टार्ट करें
echo Starting Frontend UI...
npm run dev

pause