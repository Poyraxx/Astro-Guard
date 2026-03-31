# BKZS Guard

BKZS Guard, BKZS sinyal dogrulama ve anti-spoofing icin tasarlanmis mikro-katmanli bir demo platformudur. Sistem, tek parse + tek feature cikarimi yaklasimiyla gelen akisi hizli sekilde degerlendirir ve ilk basarisiz katmanda erken durdurma uygular.

## Ozellikler

- 13 mikro-katmanli karar mimarisi
- Shadow Lane + Epoch Bait Chain tabanli deception
- Credential-valid breach ve sifre sizintisi suphe uyarisi
- Trust Mesh ve quorum mantigi
- Holdover ve response mode gecisleri
- Mission Envelope Engine
- Trust Bulletin loader ve threshold override
- Forensic Black Box case feed
- Digital Twin Router ile kontrollu golge ortama yonlendirme ve threat intel toplama
- Split-Plane Relay ile temiz veriyi guvenli hatta, saldirgani shadow hatta ayirma
- Turksat / Gokturk / IMECE icin kamuya acik teknik ozelliklerden turetilmis uydu profilleri
- Streamlit tabanli operasyon ve juri paneli
- Iki bilgisayarla calisan `remote_attack_node` saldiri dugumu ve masaustu saldiri konsolu
- UDP/TCP adaptor ve peer feed adaptor
- Aciklanabilir, deterministik karar kayitlari

## Kurulum

```bash
pip install -e .
```

## Calistirma

```bash
python -m streamlit run streamlit_app.py
```

Varsayilan operator sifresi: `bkzs-demo-ui`

Varsayilan sinyal zarfi sifresi: `bkzs-demo-signal`

Ham veri su formatta gelmelidir:

```text
<sifre_ilk_yari><json_paket><sifre_son_yari>
```

Bu zarfi tasimayan veri, JSON parse edilmeden once Katman 1'de reddedilir.

## Yeni Savunma Katmanlari

1. Sinyal zarfi
2. JSON parse
3. Sema kapisi
4. Kaynak kimligi
5. Adaptif kilit
6. Deception lane
7. Yetki ve butunluk
8. Tazelik ve replay
9. RF sagligi
10. Mekansal tutarlilik
11. Saat ve holdover
12. Trust Mesh
13. Mission Envelope
   - Secili uydu profiline gore bant, yÃ¶rÃ¼nge, protokol ve sensor metadata dogrulamasi

## Ornek Dosyalar

- `samples/mission_envelope.json`
- `samples/trust_bulletin.json`

## Test

```bash
python -m unittest discover -s tests -v
```

## Diger Bilgisayardan Ag Testi

1. Ana bilgisayarda uygulamayi acin:

```bash
python -m streamlit run streamlit_app.py
```

2. Juri ekranindan veya sol panelden uygun uydu profilini secin.

3. `Gercek Adaptor` sekmesinde:
   - Protokol olarak once `udp` secin
   - Host olarak `0.0.0.0` veya ana bilgisayarin kendi yerel IP adresini kullanin
   - Port olarak ornegin `9000` secin
   - Sonra `Agi Dinle ve Isle` butonuna basin

4. Diger bilgisayara sadece `remote_attack_node/` klasorunu kopyalayin:

```bash
cd remote_attack_node
python attack_console.py
```

Bu masaustu arayuz:

- saldiri paketlerini yollar
- ana bilgisayardan gelen karar akisini dinler
- engellenen ve gecen paketleri ayri panellerde gosterir
- secure/shadow plane relay trafigini de izler

Temiz normal trafik gondermek ve kabul edilenleri ayri dosyaya yazmak icin:

```bash
cd remote_attack_node
python normal_sender.py
```

Bu script kabul edilen paketleri `remote_attack_node/success_logs/` altina kaydeder.
`Ctrl+C` ile durdurulana kadar surekli normal trafik yollar.

Isterseniz terminal komutlariyla da gonderebilirsiniz:

```bash
python remote_signal_client.py --host ANA_BILGISAYAR_IP --port 9000 --protocol udp --mode normal --count 3
python remote_signal_client.py --host ANA_BILGISAYAR_IP --port 9000 --protocol udp --mode mission-breach --satellite-profile turksat-6a --count 2
python remote_signal_client.py --host ANA_BILGISAYAR_IP --port 9000 --protocol udp --mode shadow-contact --count 2
```

5. TCP denemesi icin ayni komutlarda `--protocol tcp` kullanin.

6. Ana bilgisayarda karar ve relay akisini ikinci bilgisayara yollamak icin su ortam degiskenlerini acin:

```bash
set BKZS_RELAY_ENABLED=1
set BKZS_SECURE_RELAY_HOST=IKINCI_BILGISAYAR_IP
set BKZS_SECURE_RELAY_PORT=9101
set BKZS_SHADOW_RELAY_HOST=IKINCI_BILGISAYAR_IP
set BKZS_SHADOW_RELAY_PORT=9102
set BKZS_DECISION_FEED_ENABLED=1
set BKZS_DECISION_FEED_HOST=IKINCI_BILGISAYAR_IP
set BKZS_DECISION_FEED_PORT=9200
```

7. Sadece ham relay portlarini terminalden gozlemek isterseniz:

```bash
cd remote_attack_node
python relay_sink.py --protocol udp --port 9101 --label secure-plane
python relay_sink.py --protocol udp --port 9102 --label shadow-plane
```

Varsayilan istemci degerleri:

- signal secret: `bkzs-demo-signal`
- session nonce: `bkzs-demo-session`
- op_code: `BKZS-DEMO-2026`

Eger bunlari UI'den degistirdiyseniz istemci komutuna ayni degerleri `--signal-secret`, `--session-nonce` ve `--op-code` ile verin.
