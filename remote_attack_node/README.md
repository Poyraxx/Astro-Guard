# Remote Attack Node

Bu klasor, ikinci bilgisayardan BKZS Guard sistemine kontrollu trafik gondermek icin hazirlanmistir.

Bu klasor tek basina tasinabilir. Tum repo kopyalamak gerekmez.

Ana panel calistiginda `attack_target_profile.json` dosyasi otomatik guncellenir.
Saldiri konsolu ve istemci bu dosyayi okuyup host, port, profil ve sifre alanlarini otomatik doldurur.

## Gerekenler

- Python 3.11+

## Kurulum

Ek paket gerekmez. Standart Python yeterlidir.

## Grafik Arayuz

Terminal yerine masaustu arayuz kullanmak icin:

```bash
python attack_console.py
```

Bu arayuz:

- paket gonderir
- karar akisini dinler
- engellenen ve gecen trafigi ayri gosterir
- secure-plane ve shadow-plane relay akisini izler

## Temiz Normal Trafik Gonderici

Sadece temiz normal veri gondermek ve kabul edilenleri ayri dosyaya yazmak icin:

```bash
python normal_sender.py
```

Bu script:

- sadece `normal` paket yollar
- `Ctrl+C` ile durdurulana kadar surekli calisir
- her batch'te sequence ilerleyerek devam eder; replay gibi gorunmez
- karar feed'den `accepted` olanlari toplar
- kabul edilenleri `success_logs/accepted_normal_*.jsonl` dosyasina yazar
- ozet bilgiyi `success_logs/summary_*.json` dosyasina cikarir

## Gonderilebilen Modlar

- `normal`
- `unauthorized`
- `jam`
- `replay`
- `shadow-contact`
- `mission-breach`
- `mesh-divergence`

## Ornek Komutlar

UDP normal trafik:

```bash
python remote_signal_client.py --host 192.168.1.50 --port 9000 --protocol udp --mode normal --count 3 --satellite-profile turksat-6a
```

UDP mission breach:

```bash
python remote_signal_client.py --host 192.168.1.50 --port 9000 --protocol udp --mode mission-breach --count 2 --satellite-profile turksat-6a
```

UDP shadow-contact:

```bash
python remote_signal_client.py --host 192.168.1.50 --port 9000 --protocol udp --mode shadow-contact --count 2 --satellite-profile turksat-6a
```

TCP jam:

```bash
python remote_signal_client.py --host 192.168.1.50 --port 9000 --protocol tcp --mode jam --count 2 --satellite-profile imece
```

## Relay Sink

Secure ve shadow relay portlarini gozlemek icin:

```bash
python relay_sink.py --protocol udp --port 9101 --label secure-plane
python relay_sink.py --protocol udp --port 9102 --label shadow-plane
```

## Varsayilan Degerler

- signal secret: `bkzs-demo-signal`
- session nonce: `bkzs-demo-session`
- op_code: `BKZS-DEMO-2026`

Eger ana bilgisayardaki UI'de bu degerleri degistirdiysen, istemci komutuna da ayni degerleri vermen gerekir:

```bash
--signal-secret ...
--session-nonce ...
--op-code ...
```

## Ana Bilgisayarda Acilacak Ortam Degiskenleri

Karar akisi ve relay olaylarini masaustu arayuze almak icin ana bilgisayarda sunlari ac:

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
