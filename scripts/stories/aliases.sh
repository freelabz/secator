#$ delay 5

#$ expect \$
secator x httpx mydomain.com:8080
#$ expect \$

secator u enable-aliases && . ~/.secator/.aliases # we can wrap available tasks as aliases
#$ expect \$

httpx --help # httpx is now secator, you don't need the prefix 'secator x' anymore
#$ expect \$

httpx mydomain.com:8080 -orig # in case you want to get the original httpx output
#$ expect \$

listw # show available workflows, same as secator w
#$ expect \$
#$ wait 3000