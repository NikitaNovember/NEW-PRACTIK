import fs from 'fs-extra'
import path from 'path'

import axios from 'axios'
import urlencode from 'urlencode'

export let test = true

var appDir = path.dirname(import.meta.url);
appDir = appDir.split('///')
appDir = appDir[1]

if (!test){
  appDir = "//"+appDir
}

console.log(appDir);

function curdate(minute){
    minute = (minute < 10) ? '0' + minute : minute;
    return minute;
  }
  
export function mlog (par) {
    let datecreate = new Date();
    let texta = `\n ${curdate(datecreate.getHours())}:${curdate(datecreate.getMinutes())}:${curdate(datecreate.getSeconds())}`;
    let obj = arguments;
  
    for (const key in obj) {
      if (typeof obj[key]=='object') {
        for (const keys in obj[key]){
          texta = `${texta} \n ${keys}:${obj[key][keys]}`
        }
      } else {
        texta = `${texta} ${obj[key]}`
      }
      
    } 
    fs.writeFileSync(path.join(appDir, 'logs',`${curdate(datecreate.getDate())}.${curdate(datecreate.getMonth()+1)} log.txt`),
    texta,
    {
      encoding: "utf8",
      flag: "a+",
      //mode: 0o666
    });
  
    console.log(texta);
    return texta
  }

export function say(msg,all=true) {
  var tgnum = [304622290,5662630619]
  if (all===true){
    tgnum.forEach(element => {
      setTimeout(() => sendtg(element,msg), 1500);
    });
  } else{
    setTimeout(() => sendtg(tgnum[0],msg), 1500);
  }
  
}