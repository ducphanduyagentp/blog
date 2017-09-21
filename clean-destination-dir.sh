cd public
find . -type f -not -name "CNAME" -not -name ".git" -not -name "." | xargs rm
find . -type d -not -name "CNAME" -not -name ".git" -not -name "." | xargs rm -rf

