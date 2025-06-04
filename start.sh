#!/bin/bash

kong migrations list
code=$?
echo CODE=$code

[[ $code -eq 3 ]] && echo "BOOTSTRAP & UP & FINISH" && kong migrations bootstrap && kong migrations up && kong migrations finish
[[ $code -eq 4 ]] && echo "FINISH" && kong migrations finish
[[ $code -eq 5 ]] && echo "UP & FINISH" && kong migrations up && kong migrations finish

kong start --nginx-conf custom-nginx.template
