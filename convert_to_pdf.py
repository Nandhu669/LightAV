"""
Convert Technical Report TXT to PDF
"""

from fpdf import FPDF
import sys

class PDF(FPDF):
    def header(self):
        # Arial bold 15
        self.set_font('Arial', 'B', 12)
        # Move to the right
        self.cell(80)
        # Title
        self.cell(30, 10, 'LightAV Technical Implementation Report', 0, 0, 'C')
        # Line break
        self.ln(20)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def txt_to_pdf(txt_file, pdf_file):
    pdf = PDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Read text file
    with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Set font
    pdf.set_font('Arial', '', 10)
    
    # Add content
    for line in lines:
        # Handle long lines
        if len(line) > 100:
            pdf.set_font('Arial', '', 8)
        else:
            pdf.set_font('Arial', '', 10)
        
        # Add line to PDF
        try:
            pdf.cell(0, 5, line.strip(), ln=True)
        except:
            # Skip problematic characters
            pdf.cell(0, 5, line.strip().encode('ascii', 'ignore').decode(), ln=True)
        
        # Add new page if needed
        if pdf.get_y() > 270:
            pdf.add_page()
    
    # Save PDF
    pdf.output(pdf_file)
    print(f"PDF created: {pdf_file}")

if __name__ == "__main__":
    txt_to_pdf(
        'TECHNICAL_IMPLEMENTATION_REPORT.txt',
        'TECHNICAL_IMPLEMENTATION_REPORT.pdf'
    )
