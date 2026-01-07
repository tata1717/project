# PWA Icons

โฟลเดอร์นี้ใช้เก็บไอคอนสำหรับ Progressive Web App (PWA)

## ไอคอนที่ต้องการ

คุณต้องสร้างไอคอนขนาดต่อไปนี้:

- `icon-72x72.png` - 72x72 pixels
- `icon-96x96.png` - 96x96 pixels
- `icon-128x128.png` - 128x128 pixels
- `icon-144x144.png` - 144x144 pixels
- `icon-152x152.png` - 152x152 pixels
- `icon-192x192.png` - 192x192 pixels (สำคัญที่สุด)
- `icon-384x384.png` - 384x384 pixels
- `icon-512x512.png` - 512x512 pixels (สำคัญที่สุด)

## วิธีสร้างไอคอน

1. เตรียมรูปภาพต้นฉบับขนาดอย่างน้อย 512x512 pixels
2. ใช้เครื่องมือออนไลน์เช่น:
   - https://www.pwabuilder.com/imageGenerator
   - https://realfavicongenerator.net/
   - https://www.favicon-generator.org/
3. หรือใช้ ImageMagick:
   ```bash
   convert icon.png -resize 192x192 icon-192x192.png
   ```

## หมายเหตุ

- ไอคอนควรเป็น PNG format
- ใช้สีที่สอดคล้องกับธีมของเว็บไซต์
- ไอคอน 192x192 และ 512x512 เป็นขนาดที่สำคัญที่สุด

