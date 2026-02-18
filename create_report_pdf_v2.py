"""
Convert Technical Report TXT to PDF with Unicode support
"""

from fpdf import FPDF
from datetime import datetime

class ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        if self.page_no() == 1:
            self.set_font('Arial', 'B', 16)
            self.cell(0, 10, 'LightAV Technical Implementation Report', new_x="LMARGIN", new_y="NEXT", align='C')
            self.set_font('Arial', '', 10)
            self.cell(0, 5, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', new_x="LMARGIN", new_y="NEXT", align='C')
            self.ln(10)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def clean_for_pdf(text):
    """Remove or replace Unicode characters that PDF doesn't support"""
    # Replace common Unicode characters
    replacements = {
        '\u251c': '+',  # Box drawing characters
        '\u2500': '-',
        '\u2502': '|',
        '\u2514': '+',
        '\u2518': '+',
        '\u250c': '+',
        '\u2510': '+',
        '\u2713': 'OK',
        '\u2717': 'X',
        '\u2718': 'X',
        '\u2714': 'OK',
        '\u26a0': '!',
        '\u2716': 'X',
        '\u2715': 'X',
        '\u2705': 'OK',
        '\u274c': 'X',
        '\u2714': 'OK',
        '\u25cf': '*',
        '\u25cb': 'o',
        '\u25b6': '>',
        '\u25b8': '>',
        '\u25ba': '>',
        '\u2192': '->',
        '\u2190': '<-',
        '\u2191': '^',
        '\u2193': 'v',
        '\u2013': '-',
        '\u2014': '-',
        '\u2018': "'",
        '\u2019': "'",
        '\u201c': '"',
        '\u201d': '"',
        '\u2026': '...',
        '\u00a9': '(c)',
        '\u00ae': '(R)',
        '\u2122': '(TM)',
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    # Remove any remaining non-ASCII characters
    text = text.encode('ascii', 'ignore').decode('ascii')
    
    return text

def create_pdf():
    pdf = ReportPDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 9)
    
    # Read and process the text file
    with open('TECHNICAL_IMPLEMENTATION_REPORT.txt', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Clean content for PDF
    content = clean_for_pdf(content)
    
    # Split into lines
    lines = content.split('\n')
    
    # Process each line
    for line in lines:
        line = line.rstrip()
        
        # Skip empty lines but add spacing
        if not line:
            pdf.ln(2)
            continue
        
        # Detect section headers
        if line.startswith('=' * 20):
            pdf.set_font('Arial', 'B', 12)
            pdf.ln(3)
        elif line.startswith('-' * 20):
            pdf.set_font('Arial', 'B', 10)
        elif line.startswith('    ') and not line.startswith('        '):
            pdf.set_font('Arial', '', 9)
        else:
            pdf.set_font('Arial', '', 9)
        
        # Handle line length
        if len(line) > 120:
            # Wrap long lines
            words = line.split(' ')
            current_line = ''
            for word in words:
                if len(current_line + ' ' + word) > 115:
                    pdf.cell(0, 4, current_line, new_x="LMARGIN", new_y="NEXT")
                    current_line = word
                else:
                    current_line += ' ' + word if current_line else word
            if current_line:
                pdf.cell(0, 4, current_line, new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, 4, line, new_x="LMARGIN", new_y="NEXT")
        
        # Add new page if needed
        if pdf.get_y() > 270:
            pdf.add_page()
    
    # Save the PDF
    output_file = 'TECHNICAL_IMPLEMENTATION_REPORT.pdf'
    pdf.output(output_file)
    print(f"✅ PDF Report Generated Successfully!")
    print(f"📄 File: {output_file}")
    print(f"📊 Size: {pdf.page_no()} pages")

if __name__ == "__main__":
    create_pdf()
