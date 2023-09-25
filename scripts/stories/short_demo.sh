#$ delay 5

#$ wait 1000
secator -nb x naabu mydomain.com -raw | secator x httpx  # port + HTTP discovery
#$ expect \$

secator x ffuf http://mydomain.com:3000/FUZZ -fs 1987,3103 -mc 200 -quiet  # fuzzing
#$ expect \$

secator w host_recon mydomain.com -rl 100  # host recon workflow
#$ expect \$

#$ wait 1000