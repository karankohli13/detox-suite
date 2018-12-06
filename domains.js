const fs = require('fs');
const needle = require('needle');
const async = require("async");
const request = require('superagent')
const chalk = require('chalk');
const parse = require('csv-parse');
const cluster = require('cluster');
const dig = require('node-dig-dns');
const subquest = require('subquest');
const json2csv = require('json2csv').parse;
const util = require('util');
const DNSScanner = require('dns-scanner/src');
const { StringStream } = require("scramjet");
const _ = require('lodash');
var numCPUs = require('os').cpus().length;
const log = console.log;
const { Transform, Readable } = require('stream');


// const target = 'rambler.ru';
// const scanner = new DNSScanner({
//     target,
//     prefixes: ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop'],
//     concurrency: 100,
// });

// scanner.start();

// scanner.on('progress', ({ current, total, percent }) => {
//   console.log(current)
//     // on each prefix processed
// });

// scanner.on('item', ({ address, ips }) => {
//     console.log(address);
//     console.log(ips);
//     // on found domain-item
// });

// scanner.on('done', res => {
//     // on end of scanning
// });

// scanner.on('error', res => {
//     // on any errors
// });


if (cluster.isMaster) {
  log(chalk.blue("CPU's:  " + numCPUs));
  masterProcess();
  // Be notified when worker processes die.
  cluster.on('death', function(worker) {
    console.log('Worker ' + worker.pid + ' died.');
  });
} else {
  childProcess();
}



async function masterProcess() {
  console.log(`Master ${process.pid} is running`);
  let domains = await readFile('domains.txt');
  numCPUs = domains.length > numCPUs ? numCPUs : domains.length;
  for (let i = 0; i < numCPUs; i++) {
    console.log(`Forking process number ${i+1}...`);
    var new_worker_env = {};
    new_worker_env["WORKER_NAME"] = i;
    const worker = cluster.fork(new_worker_env);
    let factor = Math.floor(domains.length / (numCPUs));
    let remainder = domains.length - ((numCPUs - 1) * factor);
    if (i < numCPUs - 1)
      worker.send(domains.slice(i, i + factor));
    else worker.send(domains.slice(i, i + remainder));
  }
}

function childProcess() {
  process.on('message', data => {

    StringStream.from(data)
      .pipe(needleYo)
      .pipe(processResponse)
      .pipe(fs.createWriteStream('result.csv'))
  });
}


const needleYo = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  async transform(chunk, encoding, callback) {
    try{
    let response = await needle('get', 'https://' + chunk, { parse: true });
    this.push({ host: response.host || response.hostname || 'https://' + chunk, port: response.port, status: response.statusCode, headers: response.headers, location: response.location });
    response = await needle('get', 'http://' + chunk, { parse: true });
    this.push({ host: response.host || response.hostname || 'http://' + chunk, port: response.port, status: response.statusCode, headers: response.headers, location: response.location });
    callback();
    }
    catch(err){
      this.push({ host: err.host || chunk, port: err.port, code: err.code });
      callback();
    }
  }
});


const processResponse = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  transform(chunk, encoding, callback) {
    this.push(json2csv(chunk))
    callback();
  }
});


async function readFile(file) {
  return new Promise(resolve => {
    let header;
    const label = `read2-${file}`;
    console.time(label);
    const stream = fs.createReadStream(file, { encoding: 'utf8' });
    stream.on('data', data => {
      header = data.split(/\n/).filter(Boolean);
      stream.destroy();
    });
    stream.on('close', () => {
      console.timeEnd(label);
      resolve(header);
    });
  });
};

async function writeCsv(file, content) {
  return new Promise(resolve => {
    let csvStream = csv.createWriteStream({ headers: true }),
      writableStream = fs.createWriteStream(file + ".csv");

    writableStream.on("finish", function() {
      console.log("DONE!");
      resolve();
    });

    csvStream.pipe(writableStream);
    csvStream.write({ a: "a0", b: "b0" });
    csvStream.write({ a: "a1", b: "b1" });
    csvStream.write({ a: "a2", b: "b2" });
    csvStream.write({ a: "a3", b: "b4" });
    csvStream.write({ a: "a3", b: "b4" });
    csvStream.end();
  });
}



const getRawResponse = domain => {
  return new Promise((resolve, reject) => {
    request.get(`https://crt.sh/?q=%.${domain}&output=json`)
      .then(res => resolve(res.text))
      .catch(err => {
        if (err.statusCode !== 200) return reject(err)
        return resolve(err.rawResponse)
      })
  })
}


const clearUrl = target => {
  let domain = target
  if (/^(https?:|www\.)/i.test(target)) domain = url.parse(target).hostname || domain
  // domain = domain.replace(/.*www\./i, '') // TODO: not need multiple replace
  return domain
};


const findSubdomains = async function(a) {
  if (!a) {
    console.log(`usage: find-subdomains DOMAIN`)
    process.exit(1)
  }

  const target = a;
  const domain = clearUrl(target)

  // console.log(`[*] TARGET: ${domain}\n`)

  let response
  try {
    response = await getRawResponse(domain);
  } catch (err) {
    console.log(err)
    console.log(`[X] Information not available! (${err.statusCode})`)
    return process.exit(1)
  }

  const jsonData = JSON.parse(`[${response.trim().replace(/}{/g, '},{')}]`)
  const subdomains = Array.from(new Set(jsonData.map(_ => _.name_value))).sort((a, b) => a > b)
  return subdomains;
  // for (const _ of subdomains) console.log(`[+] ${_}`)
  // console.log('\n[*]  Done. Have a nice day! ;).')
}
