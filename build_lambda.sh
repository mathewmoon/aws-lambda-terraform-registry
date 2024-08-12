find ./ -name __pycache__ |xargs -I {} rm -rf {}

rm -rf build || echo ""
pip3 install --no-cache --no-deps -t build .
cd build
find ./ -name __pycache__ |xargs -I {} rm -rf {}
zip -r ../registry.zip .
cd ..
rm -rf build
aws --no-paginate lambda update-function-code --function-name terraform-registry --zip-file fileb://./registry.zip --publish
rm -rf build
rm -rf dist
