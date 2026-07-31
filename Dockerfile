FROM php:8.2-apache

# Instalar dependências para o Puppeteer (Chrome) e Node.js
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    libx11-xcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxi-dev \
    libxtst6 \
    libnss3 \
    libcups2 \
    libxss1 \
    libxrandr2 \
    libasound2 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libpangocairo-1.0-0 \
    libgtk-3-0 \
    libgbm1 \
    fonts-liberation \
    libappindicator3-1 \
    xdg-utils \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Instalar Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs

# Configurar diretório de trabalho
WORKDIR /var/www/html

# Copiar os arquivos do projeto
COPY . /var/www/html/

# Instalar pacotes NPM (Puppeteer)
RUN npm install

# Configurar o Apache para usar a porta do Render (variavel de ambiente PORT)
RUN sed -i 's/80/${PORT}/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf

# Habilitar o mod_rewrite do Apache (necessário para muitas APIs PHP)
RUN a2enmod rewrite

# Mudar o dono dos arquivos para o Apache
RUN chown -R www-data:www-data /var/www/html

