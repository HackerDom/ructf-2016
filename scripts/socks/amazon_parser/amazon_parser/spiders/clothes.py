# -*- coding: utf-8 -*-
import scrapy
import re

from amazon_parser.items import ClothesItem


class ClothesSpider(scrapy.Spider):
    name = "clothes"
    allowed_domains = ["amazon.com"]
    start_urls = (
        'https://www.amazon.com/s/ref=sr_ex_n_0?rh=n%3A7141123011%2Ck%3Aclothes&bbn=7141123011&keywords=clothes&ie=UTF8&qid=1460049149',
    )

    ITEM_URL = re.compile(r'amazon.com/[A-Z]')
    def parse(self, response):
        bad_urls = ('www.amazon.com/gp', 'amazon.com/s')
        for href in response.css("a::attr('href')"):
            url = response.urljoin(href.extract())
            if "page=1" in url:
                continue

            if "page" in url:
                yield scrapy.Request(response.urljoin(url))
                continue

            found_bad = False
            for bad_url in bad_urls:
                if bad_url in url:
                    found_bad = True
                    break

            if found_bad:
                continue

            if self.ITEM_URL.search(url):
                yield scrapy.Request(response.urljoin(url), self.parse_item)

    def parse_item(self, response):
        clothes = ClothesItem()
        clothes['url'] = response.url
        clothes['title'] = response.css("span[id*=productTitle]::text").extract()[0]

        fields = []
        for field in response.css("div[id*=feature-bullets] span[class*=a-list-item]::text").extract():
            fields.append(field.strip())

        if fields:
            clothes['fields'] = fields

        yield clothes
