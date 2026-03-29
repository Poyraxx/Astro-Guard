# BKZS ESP8266 Gonderici

Bu klasor, elindeki ESP8266 tabanli kartin BKZS Guard ana istasyonuna dogru ve kabul edilebilir temiz veri yollamasi icin hazirlandi.

## Dosyalar

- `BKZS_ESP8266_Sender/BKZS_ESP8266_Sender.ino`
- `BKZS_ESP8266_Sender/bkzs_esp8266_profile.h`
- `BKZS_ESP8266_Sender/bkzs_wifi_secrets.h`

## Hangi Board Paketi?

Bu sketch `ESP32` icin degil, `ESP8266` icindir.

Arduino IDE:

1. `File > Preferences`
2. `Additional Boards Manager URLs` alanina su adresi ekle:
   `http://arduino.esp8266.com/stable/package_esp8266com_index.json`
3. `Tools > Board > Boards Manager`
4. `esp8266 by ESP8266 Community` paketini kur
5. `Tools > Board` menusunden genelde su kartlardan biri secilir:
   - `NodeMCU 1.0 (ESP-12E Module)`
   - veya `Generic ESP8266 Module`

CH340'li kartlarin cogu icin ilk denenecek secim:
- `NodeMCU 1.0 (ESP-12E Module)`

## Ana PC

Ana uygulamada:

- `Gercek Adaptor`
- `Protokol = udp`
- `Host = 0.0.0.0`
- `Port = 9000`
- `Dinlemeyi Baslat`

## ESP8266

1. `BKZS_ESP8266_Sender.ino` dosyasini ac.
2. `bkzs_wifi_secrets.h` icine kendi Wi-Fi bilgilerini yaz.
3. `bkzs_esp8266_profile.h` ana panel acildikca otomatik guncellenir.
4. Kart olarak `NodeMCU 1.0 (ESP-12E Module)` sec.
5. COM portu sec.
6. Upload yap.
7. Seri monitoru `115200` ile ac.

## Notlar

- Kaynak adi `bkzs-esp8266-1` olarak ayarlandi.
- Bu kaynak BKZS tarafinda guvenilir kaynak listesine eklendi.
- Kart acilisinda eski zincir state'i EEPROM'dan okunur.
- FLASH/BOOT tusuna basili acarsan zincir state temizlenir ve genesis'ten yeniden baslar.

