# scamdown

Dolandırıcılık ve oltalama (phishing) linklerini, kapatabilecek herkese tek seferde bildirir.

Bir link, sahte SMS metni, ekran görüntüsü ya da phishing e-postası verirsin. scamdown yönlendirmeleri takip eder, kimlerin işin içinde olduğunu bulur (kara listeler, hosting, CDN, domain firması, IP sahibi), her birine istediği kanıtlarla bir bildirim yazar ve otomatik gönderilebilenleri gönderir. Geri kalanlar doldurulmuş form ya da e-posta olarak açılır.

## Sıra neden böyle

1. **Kara listeler.** Netcraft, Google Safe Browsing ve Microsoft SmartScreen siteye tüm tarayıcılarda kırmızı uyarı koyar, çoğu zaman bir saat içinde. Site kapanmadan insanları korur.
2. **Hosting / platform** (Vercel, Netlify, GitHub Pages, Firebase, AWS...). Siteyi siler.
3. **Domain firması.** Domaini askıya alır; site, alt alan adları ve e-postası birlikte kapanır.
4. **Cloudflare.** Sadece aracıysa siteyi silemez ama bildirimi asıl hostinge iletir ve uyarı sayfası koyar.
5. **IP sahibi.** Site düz bir sunucudaysa harekete geçen odur.
6. **USOM** (`--country TR`). Listesi Türkiye'deki internet sağlayıcılarında erişimi engeller.

## Kullanım

```sh
npx scamdown report "hxxps://usps-redelivery[.]xyz"      # önizleme, hiçbir şey göndermez
npx scamdown init                                         # ad, e-posta, isteğe bağlı SMTP ve API anahtarları
npx scamdown report -i sms.png --country TR --send        # ekran görüntüsünden linkleri okur ve gönderir
npx scamdown check                                        # bildirdiklerinden hangileri kapandı
npx scamdown web                                          # tarayıcıda: ekran görüntüsünü yapıştır, düğmelere bas
```

Ekran görüntüsü `ANTHROPIC_API_KEY` varsa Claude ile, yoksa `tesseract` ile okunur.

Claude Desktop / Claude Code için MCP: `claude mcp add scamdown -- npx -y scamdown mcp`. Sonra sohbete ekran görüntüsünü bırakıp "bunu bildir" demen yeterli.

## Sorumlu kullanım

Bildirimler senin adını ve e-postanı taşır. Yalnız kendi gördüğün linkleri bildir, aynı linki tekrar tekrar gönderme. scamdown bilgilerini site sahibine asla göndermez.

Para kaybettiysen önce bankanı ara, sonra savcılığa ya da e-Devlet üzerinden şikâyet et.
