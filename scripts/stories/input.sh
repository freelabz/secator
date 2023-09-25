#$ delay 5

secator x httpx http://mydomain.com:3000 # single target
#$ expect \$

secator x httpx http://mydomain.com:3000,http://mydomain.com:8080 # ... or a comma-separated list of targets
#$ expect \$

secator x httpx urls.txt # ... or a file containing targets
#$ expect \$

cat urls.txt | secator x httpx # ... or feed targets through stdin
#$ expect \$

#$ wait 1000