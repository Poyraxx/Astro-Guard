# BKZS ESP32 Gonderici

Bu klasor, ESP32 kartinin BKZS Guard ana istasyonuna dogru ve kabul edilebilir normal veri yollamasi icin hazirlandi.

## Dosyalar

- `BKZS_ESP32_Sender/BKZS_ESP32_Sender.ino`
- `BKZS_ESP32_Sender/bkzs_esp32_profile.h`
- `BKZS_ESP32_Sender/bkzs_wifi_secrets.h`

## Calisma Mantigi

- ESP32, ana PC'deki mevcut `UDP / TCP Adaptor` ile konusur.
- Varsayilan kurulum `UDP 9000` uzerindendir.
- Kart, BKZS sinyal zarfi + JSON + challenge proof + flow tag + checksum uretir.
- Zincir state'ini kendi icinde saklar; yeniden baslatmalarda dogru akisa devam etmeye calisir.

## Ana PC

Ana uygulamada:

- `Gercek Adaptor`
- `Protokol = udp`
- `Host = 0.0.0.0`
- `Port = 9000`
- `Dinlemeyi Baslat`

## ESP32

1. Arduino IDE veya PlatformIO ile `BKZS_ESP32_Sender.ino` ac.
2. Arduino IDE'de `File > Preferences > Additional Boards Manager URLs` alanina su adresi ekle:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. `Tools > Board > Boards Manager` icinden `esp32 by Espressif Systems` paketini kur.
4. `Tools > Board` menusunden `ESP32 Dev Module` veya elindeki karta uygun ESP32 modelini sec.
5. `bkzs_wifi_secrets.h` icine kendi Wi-Fi bilgilerini yaz.
6. `bkzs_esp32_profile.h` dosyasi ana panel acildikca guncellenir.
7. Kodu karta yukle.
8. Seri monitoru `115200` baud ile ac.

## Notlar

- Kart varsayilan olarak `bkzs-esp32-1` kaynagi ile gonderim yapar.
- Bu kaynak BKZS tarafinda guvenilir kaynak listesine eklendi.
- Ana sistem restart edilip kart eski zincirle devam ederse ilk paketlerden biri red olabilir.
- BOOT tusuna basili acarsan kart zincir state'ini temizleyip genesis'ten yeniden baslar.
