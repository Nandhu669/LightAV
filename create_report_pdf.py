"""
Convert Technical Report TXT to PDF with proper formatting
"""

from fpdf import FPDF
from datetime import datetime

class ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        # Only add header on first page
        if self.page_no() == 1:
            self.set_font('Courier', 'B', 16)
            self.cell(0, 10, 'LightAV Technical Implementation Report', ln=True, align='C')
            self.set_font('Courier', '', 10)
            self.cell(0, 5, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', ln=True, align='C')
            self.ln(10)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Courier', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def create_pdf():
    pdf = ReportPDF()
    pdf.add_page()
    pdf.set_font('Courier', '', 9)
    
    # Read and process the text file
    with open('TECHNICAL_IMPLEMENTATION_REPORT.txt', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Split into lines
    lines = content.split('\n')
    
    # Process each line
    for line in lines:
        # Clean the line
        clean_line = line.strip()
        
        # Skip empty lines but add spacing
        if not clean_line:
            pdf.ln(2)
            continue
        
        # Detect headers (lines with === or ---)
        if '=' * 10 in clean_line:
            pdf.set_font('Courier', 'B', 11)
            pdf.ln(3)
        elif '-' * 10 in clean_line:
            pdf.set_font('Courier', 'B', 10)
        else:
            pdf.set_font('Courier', '', 9)
        
        # Handle long lines by wrapping
        if len(clean_line) > 95:
            # Split long lines
            words = clean_line.split(' ')
            current_line = ''
            for word in words:
                if len(current_line + ' ' + word) > 95:
                    pdf.cell(0, 4, current_line, ln=True)
                    current_line = word
                else:
                    current_line += ' ' + word if current_line else word
            if current_line:
                pdf.cell(0, 4, current_line, ln=True)
        else:
            pdf.cell(0, 4, clean_line, ln=True)
        
        # Add new page if needed
        if pdf.get_y() > 270:
            pdf.add_page()
    
    # Save the PDF
    output_file = 'TECHNICAL_IMPLEMENTATION_REPORT.pdf'
    pdf.output(output_file)
    print(f"✅ PDF Report Generated Successfully!")
    print(f"📄 File: {output_file}")
    print(f"📊 Pages: {pdf.page_no()}")

if __name__ == "__main__":
    create_pdf()
