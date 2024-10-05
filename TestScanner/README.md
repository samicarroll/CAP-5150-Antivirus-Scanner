# CAP-5150-Antivirus-Scanner
Antivirus Scanner that will detect stated keywords and use pdfminer.six and PyPDF2 libraries to extract metadata from the PDFs. Also implemented routines to detect Javascript present in PDFs; alerts the user if Javascript is present in the PDF. 

**Obtaining PDFs Containing Javascript**:
[PDF Scripting](https://www.pdfscripting.com/public/Free-Sample-PDF-Files-with-scripts.cfm)
*Provides PDFs with harmless Javascript present; example PDF included in TestPDFs directory*

**Install Python Libraries**: 
Libraries that will be beneficial for this project are: pdfminer.six, PyPDF2
> pip3/pip install pdfminer.six
> pip3/pip install PyPDF2
*terminal command will differ depending on pip version*