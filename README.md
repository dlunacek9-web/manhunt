# Manhunt

Hra pro 5 hráčů v prohlížeči telefonu: 2 lovci, 3 schovávači. Lovcům každou minutu přijde poloha schovávačů.

## Jak hrát

1. Jeden hráč otevře appku, zadá jméno a dá **Založit novou hru**.
2. Pošle ostatním pozvánku (odkaz), nebo jim řekne kód hry.
3. Všichni povolí polohu. Host rozdělí role, volitelně nakreslí hranice do mapy, nastaví náskok a délku hry.
4. Po spuštění mají schovávači náskok. Pak každý telefon jednou za minutu odešle polohu.
5. Chyceného označí lovec, nebo schovávač sám. Lovci vyhrají, když chytí všechny. Schovávači vyhrají, když vyprší čas.

**Telefon musí zůstat odemčený a appka otevřená.** Prohlížeč v zamčeném telefonu polohu neposílá. Appka drží displej rozsvícený sama. Lovec u hráče, který přestal posílat, uvidí varování.

## Jak to funguje

Statický web na GitHub Pages, žádný vlastní server. Telefony si posílají zprávy přes dva veřejné MQTT brokery (HiveMQ a EMQX) zároveň. Všechny zprávy jsou šifrované AES-GCM klíčem odvozeným z kódu hry, takže brokery vidí jen šifrovaná data. Poloha se odesílá jen jednou za minutu během hry a telefon ji po konci hry z brokeru smaže.

Hru hlídá jen appka, ne server. Hráč, který by uměl číst provoz vlastního telefonu, by technicky mohl zjistit i polohu lovců.

Veřejné brokery nemají žádnou garanci dostupnosti. Mapa používá OpenStreetMap.

## Spuštění lokálně

Stačí statický server, poloha ale funguje jen na `localhost` nebo přes HTTPS:

```bash
python3 -m http.server 8000
```
