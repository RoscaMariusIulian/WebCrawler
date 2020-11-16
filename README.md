# WebCrawler

## Part one

The challenge in this project was to crawl a domain, respecting the crawler rules and saving all the website files you're allowed to save. In order to send the lowest number of requests to the server a dns cache was used  (used my own dns request method for HTTP check: https://github.com/RoscaMariusIulian/DNSreq) and for page parsing I used the requests module in order to treat the redirects, errors and server errors. All the pages are saved in a folder structure resembling the URL. The project works multithreaded, assigning 1 thread for each domain it searches.

And this is how the script looks when it's working:
![image](https://user-images.githubusercontent.com/63077197/99296674-cce4b480-284f-11eb-9d94-ee2aca2b72a7.png)
