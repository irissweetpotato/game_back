# Отдельный index.html и стили под каждый домен

Теперь backend сам выбирает файл по `Host` домена.

## Куда класть файлы

Структура такая:

```text
public/
  index.html                 # общий fallback, если под домен нет отдельной папки
  styles.css                 # общий fallback-стиль
  domains/
    domain1.site/
      index.html             # откроется на https://domain1.site/
      styles.css             # откроется на https://domain1.site/styles.css
    domain2.site/
      index.html             # откроется на https://domain2.site/
      styles.css             # откроется на https://domain2.site/styles.css
```

Папка должна называться ровно как домен, без `https://` и без слеша в конце.

Примеры:

```text
public/domains/statistiks.online/index.html
public/domains/statistiks.online/styles.css

public/domains/statsgames.online/index.html
public/domains/statsgames.online/styles.css
```

Если запрос пришёл на `www.domain.site`, backend также попробует найти папку `domain.site`. И наоборот: для `domain.site` также попробует `www.domain.site`.

## Как сделать новый домен

```bash
cd /путь/к/backend
mkdir -p public/domains/example.site
cp public/domains/_template/index.html public/domains/example.site/index.html
cp public/domains/_template/styles.css public/domains/example.site/styles.css
nano public/domains/example.site/index.html
nano public/domains/example.site/styles.css
pm2 restart server1
```

## Важно по Nginx

В Nginx все домены могут дальше проксироваться на этот же Node.js backend. Главное, чтобы прокидывался Host:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

Если этого нет, backend не поймёт, с какого домена пришёл запрос.

## Что будет работать

- `https://domain1.site/` отдаст `public/domains/domain1.site/index.html`
- `https://domain1.site/styles.css` отдаст `public/domains/domain1.site/styles.css`
- `https://domain1.site/leaderboard` продолжит работать как API
- `POST /get_stats` и `POST /get` не ломаются
- если папки под домен нет, отдаётся общий `public/index.html` и общий `public/styles.css`
