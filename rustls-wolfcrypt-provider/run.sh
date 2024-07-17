dir1=.
while inotifywait -qqre modify "$dir1"; do
    cargo test
done
