while read line; do
    for word in $line; do
        echo "$word"
    done
done < dantes-inferno.txt
