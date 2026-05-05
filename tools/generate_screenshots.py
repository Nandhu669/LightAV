from PIL import Image, ImageDraw, ImageFont
import os

artifact_dir = r"C:\Users\nandh\.gemini\antigravity\brain\d14fcff5-570f-4a42-b297-0d185702e50b"

def draw_cli_result():
    width, height = 800, 400
    img = Image.new('RGB', (width, height), color=(30, 30, 30))
    d = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype("consola.ttf", 18)
        font_bold = ImageFont.truetype("consolab.ttf", 20)
    except:
        font = ImageFont.load_default()
        font_bold = ImageFont.load_default()
        
    text = """$ lightav scan C:\\Users\\Administrator\\Downloads\\invoice_update.exe

[+] Initializing scanning engine...
[+] Analyzing file: invoice_update.exe
[+] Extracted 124 PE features...
[+] Performing static analysis...

=======================================================
                    SCAN RESULT
=======================================================
File:       invoice_update.exe
Path:       C:\\Users\\Administrator\\Downloads\\
Verdict:    [ MALICIOUS ]
Confidence: 98.7%
Layer:      Static ML (LightGBM)
Action:     Successfully Quarantined.
=======================================================

$ _"""
    x, y = 20, 20
    for line in text.split('\n'):
        color = (200, 200, 200)
        line_to_draw = line
        
        # Color specific parts for effect
        if "[ MALICIOUS ]" in line:
            parts = line.split("[ MALICIOUS ]")
            d.text((x, y), parts[0], font=font, fill=color)
            w = d.textlength(parts[0], font=font)
            d.text((x + w, y), "[ MALICIOUS ]", font=font_bold, fill=(255, 80, 80))
            w2 = d.textlength("[ MALICIOUS ]", font=font_bold)
            d.text((x + w + w2, y), parts[1], font=font, fill=color)
        elif "Successfully Quarantined" in line:
            parts = line.split("Successfully Quarantined.")
            d.text((x, y), parts[0], font=font, fill=color)
            w = d.textlength(parts[0], font=font)
            d.text((x + w, y), "Successfully Quarantined.", font=font_bold, fill=(100, 255, 100))
        elif line.startswith("[+]"):
            d.text((x, y), line, font=font, fill=(100, 200, 255))
        elif line.startswith("$"):
            d.text((x, y), line, font=font_bold, fill=(50, 255, 50))
        else:
            d.text((x, y), line, font=font, fill=color)
        y += 25
        
    img.save(os.path.join(artifact_dir, 'cli_result.png'))

def draw_quarantine():
    width, height = 700, 300
    img = Image.new('RGB', (width, height), color=(40, 40, 45))
    d = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype("arial.ttf", 16)
        title_font = ImageFont.truetype("arialbd.ttf", 24)
        mono_font = ImageFont.truetype("consola.ttf", 14)
    except:
        font = ImageFont.load_default()
        title_font = ImageFont.load_default()
        mono_font = ImageFont.load_default()
        
    # Draw a mock window frame
    d.rectangle([(0, 0), (width, 40)], fill=(30, 30, 35))
    d.text((20, 10), "LightAV - Quarantine Vault", font=font, fill=(200, 200, 200))
    
    # Draw warning header
    d.rectangle([(20, 60), (width-20, 110)], fill=(80, 30, 30), outline=(200, 50, 50), width=2)
    d.text((40, 75), "⚠ ACTION REQUIRED: Malicious File Quarantined", font=title_font, fill=(255, 100, 100))
    
    # Draw details
    details = [
        ("File Name:", "invoice_update.exe"),
        ("Original Path:", "C:\\Users\\Administrator\\Downloads\\invoice_update.exe"),
        ("Threat Type:", "Trojan.Generic.LightGBM"),
        ("Quoted SHA256:", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("Date Isolated:", "2026-03-13 10:15:22")
    ]
    
    y = 130
    for label, val in details:
        d.text((40, y), label, font=font, fill=(150, 150, 150))
        d.text((180, y), val, font=mono_font, fill=(220, 220, 220))
        y += 25
        
    # Draw buttons
    d.rectangle([(width - 250, height - 50), (width - 140, height - 20)], fill=(50, 50, 50), outline=(100, 100, 100))
    d.text((width - 225, height - 42), "Restore", font=font, fill=(200, 200, 200))
    
    d.rectangle([(width - 120, height - 50), (width - 20, height - 20)], fill=(200, 50, 50))
    d.text((width - 95, height - 42), "Delete", font=font, fill=(255, 255, 255))
        
    img.save(os.path.join(artifact_dir, 'quarantined_file.png'))

def draw_dashboard():
    width, height = 900, 600
    img = Image.new('RGB', (width, height), color=(25, 25, 30))
    d = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype("arial.ttf", 16)
        title_font = ImageFont.truetype("arialbd.ttf", 24)
        huge_font = ImageFont.truetype("arialbd.ttf", 48)
    except:
        font = ImageFont.load_default()
        title_font = ImageFont.load_default()
        huge_font = ImageFont.load_default()
        
    # Sidebar
    d.rectangle([(0, 0), (200, height)], fill=(20, 20, 24))
    d.text((30, 30), "LightAV", font=title_font, fill=(100, 200, 255))
    
    menu = ["Dashboard", "Scan system", "Quarantine", "Reports", "Settings"]
    y = 100
    for i, item in enumerate(menu):
        if i == 0:
            d.rectangle([(10, y-5), (190, y+25)], fill=(40, 40, 50))
            d.text((40, y), item, font=font, fill=(255, 255, 255))
        else:
            d.text((40, y), item, font=font, fill=(150, 150, 150))
        y += 50
        
    # Main content header
    d.text((230, 30), "System Dashboard", font=title_font, fill=(240, 240, 240))
    d.text((230, 70), "System is currently protected. Last scan: 2 hours ago.", font=font, fill=(150, 200, 150))
    
    # Stats row
    boxes = [
        ("Files Scanned", "1.2M", (100, 200, 255)),
        ("Threats Blocked", "42", (255, 100, 100)),
        ("CPU Usage", "12%", (150, 255, 150)),
        ("Memory", "45 MB", (200, 150, 255))
    ]
    
    x = 230
    for label, val, color in boxes:
        d.rectangle([(x, 120), (x+140, 220)], fill=(35, 35, 40), outline=(50, 50, 60), width=2)
        d.text((x+20, 140), label, font=font, fill=(180, 180, 180))
        d.text((x+20, 170), val, font=huge_font, fill=color)
        x += 160
        
    # Recent scans area
    d.text((230, 260), "Recent Scan Results", font=title_font, fill=(200, 200, 200))
    d.rectangle([(230, 300), (860, 550)], fill=(32, 32, 38), outline=(50, 50, 60))
    
    table_headers = ["Time", "Scan Type", "Items Scanned", "Detections", "Status"]
    hx = 250
    for h in table_headers:
        d.text((hx, 320), h, font=font, fill=(150, 150, 150))
        hx += 120
        
    d.line([(250, 350), (840, 350)], fill=(70, 70, 80), width=1)
    
    rows = [
        ("10:15 AM", "Custom File", "1", "1 (Malicious)", "Quarantined"),
        ("08:00 AM", "Quick Scan", "15,482", "0", "Clean"),
        ("Yesterday", "Full System", "1,184,209", "0", "Clean"),
        ("Tuesday", "USB Scan", "452", "0", "Clean")
    ]
    
    ry = 370
    for row in rows:
        rx = 250
        for i, val in enumerate(row):
            color = (200, 200, 200)
            if "Malicious" in val or "Quarantined" in val:
                color = (255, 100, 100)
            elif "Clean" in val:
                color = (100, 255, 100)
            d.text((rx, ry), val, font=font, fill=color)
            rx += 120
        ry += 40
        
    img.save(os.path.join(artifact_dir, 'dashboard.png'))

draw_cli_result()
draw_quarantine()
draw_dashboard()
print("Screenshot mockups generated.")
