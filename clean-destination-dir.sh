cd public
find . -type f -not -name "CNAME" -not -name ".git" | xargs rm
find . -type d -not -name "CNAME" -not -name ".git" | xargs rm -rf

