#$ delay 5

#$ wait 1000
secator x naabu mydomain.com -raw | secator x httpx -raw | secator x katana -raw | secator x gf --pattern xss  # port scan + HTTP check + XSS pattern finder
#$ expect \$

#$ wait 1000
secator x subfinder wikipedia.org -raw | secator x httpx  # subdomain discovery with HTTP check
#$ expect \$

#$ wait 1000