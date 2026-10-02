# Validation Log - SafeGuard AI User Testing

> Muc tieu: kiem tra prototype voi nguoi dung that ngoai nhom, xem ho co hieu muc rui ro, ly do AI dua ra va hanh dong tiep theo trong duoi 30 giay hay khong.

## Tom tat
- So nguoi test: 5 nguoi ngoai nhom.
- Nhom kich ban: phishing link, fake bill VietQR, shipper COD, APK gia mao, input mo ho.
- Tieu chi hoi sau test:
  1. Ket qua co de hieu khong?
  2. Ban co biet nen lam gi tiep theo khong?
  3. Diem nao lam ban tin/khong tin ket qua AI?

## Bang ghi chep tinh huong test
| # | Nguoi dung | Vai tro/ngu canh | Kich ban test | Ket qua quan sat | Diem |
|---|---|---|---|---|---:|
| 1 | Nguyen Van An | Sinh vien, tung gap fake bill VietQR | Upload anh bill VietQR 2 trieu, app ngan hang chua bien dong | Hieu can kiem tra app ngan hang truoc khi giao hang | 5/5 |
| 2 | Tran Thi Binh | Nguoi mua sam online | Tin nhan CTV Shopee yeu cau dong 500k quy dam bao | Hieu red flag "coc tien/hoi thuc/chuyen khoan ca nhan" | 5/5 |
| 3 | Le Hoang Cuong | Tung gap shipper COD gia mao | Shipper bao co don COD 150k gui bao ve, bat chuyen khoan gap | Thich checklist hanh dong va canh bao khong chuyen tien voi don khong xac nhan | 5/5 |
| 4 | Pham Thanh Dung | Sinh vien | Link tai file APK VNeID/Cuc Thue tu SMS | Hieu rui ro APK ngoai store va khong bam link | 5/5 |
| 5 | Hoang Duc Anh | Hoc vien AI | Input mo ho "Alo anh oi" | Danh gia cao viec AI khong phan bua, co Confidence Low | 4.5/5 |

## Feedback chi tiet
### Feedback #1
- **Nguoi dung**: Nguyen Van An
- **Kich ban**: Fake bill VietQR.
- **Quote**: "Binh thuong thay bill co dau xanh la em tin luon, nhung AI nhac phai xem bien dong that trong app ngan hang thi em moi dung lai."
- **Diem**: 5/5

### Feedback #2
- **Nguoi dung**: Tran Thi Binh
- **Kich ban**: CTV Shopee dong quy 500k.
- **Quote**: "Risk Score va tung ly do nhu coc tien, hoi thuc, tai khoan ca nhan rat de hieu. Em biet ngay la khong nen chuyen."
- **Diem**: 5/5

### Feedback #3
- **Nguoi dung**: Le Hoang Cuong
- **Kich ban**: Shipper COD gia mao.
- **Quote**: "Phan Emergency 1 phut, 3 phut, 5 phut rat thuc te. Luc bi lua nguoi ta hay roi nen can tung buoc ngan nhu vay."
- **Diem**: 5/5

### Feedback #4
- **Nguoi dung**: Pham Thanh Dung
- **Kich ban**: APK gia mao VNeID/Cuc Thue.
- **Quote**: "Truoc gio em khong de y duoi .apk, AI giai thich file ngoai CH Play co the chiem quyen dien thoai nen em thay ro rui ro."
- **Diem**: 5/5

### Feedback #5
- **Nguoi dung**: Hoang Duc Anh
- **Kich ban**: Input mo ho.
- **Quote**: "Diem hay la AI khong noi chac chan lua dao khi thieu du lieu. Confidence Low lam minh thay he thong trung thuc hon."
- **Diem**: 4.5/5

## Changelog tu feedback
| Thay doi | Nguon feedback | Ly do |
|---|---|---|
| Bo sung/lam ro disclaimer Human-in-the-Loop | Feedback #5 | Nguoi dung can biet AI co the sai va can xac minh doc lap. |
| Lam ro Emergency Protocol 1'-3'-5'-10'-30' | Feedback #3 | Khi da mat tien, nguoi dung can quy trinh ngan, theo moc thoi gian. |
| Viet khuyen nghi hanh dong thanh checklist ngan | Feedback #1, #2 | Nguoi dung can biet "lam gi tiep theo", khong chi xem diem rui ro. |
