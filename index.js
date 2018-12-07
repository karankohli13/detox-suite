const fs = require('fs');
const needle = require('needle');
const async = require("async");
const request = require('superagent')
const chalk = require('chalk');
const cluster = require('cluster');
const { prompt } = require('enquirer');
const dig = require('node-dig-dns');
const subquest = require('subquest');
const json2csv = require('json2csv').parse;
const util = require('util');
const DNSScanner = require('dns-scanner/src');
const { StringStream, BufferStream } = require("scramjet");
const _ = require('lodash');
const detour = require('detour-stream');
var numCPUs = require('os').cpus().length;
const log = console.log;
const { Transform, Readable } = require('stream');

const crlf_payload_file = 'crlf_injection_payloads.txt';
const open_rediect_payload_file = 'open_redirect_payloads.txt';
const cname_takeover_file = 'sub-bypass.txt';

var userInput = {};


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

  const question = [{
      type: 'autocomplete',
      name: 'mode',
      message: 'Select scan mode',
      limit: 7,
      suggest(input, choices) {
        return choices.filter(choice => choice.message.startsWith(input));
      },
      choices: [
        '1.Simple Domain Response',
        '2.Domain Response with CNAME',
        '3.Domain Response with CRLF',
        '4.Domain Response with open redirection',
        '5.Domain Response Full check',
        '6.Subdomain Scanner',
        '7.Subdomain Scanner with Full check'
      ]
    },
    {
      type: 'input',
      name: 'source',
      message: 'Enter input file name (e.x: domains.txt)'
    }

  ];

  let answers = await prompt(question);

  userInput.mode = parseInt(answers.mode.split('.')[0]);
  userInput.source = answers.source || 'domains.txt';

  console.log(`Master ${process.pid} is running`);
  let domains = await readFile(userInput.source);
  numCPUs = domains.length > numCPUs ? numCPUs : domains.length;
  for (let i = 0; i < numCPUs; i++) {
    console.log(`Forking process number ${i+1}...`);
    var new_worker_env = {};
    new_worker_env["WORKER_NAME"] = i;
    const worker = cluster.fork(new_worker_env);
    let factor = Math.floor(domains.length / (numCPUs));
    let remainder = domains.length - ((numCPUs - 1) * factor);
    if (i < numCPUs - 1)
      worker.send({ domains: domains.slice(i, i + factor), userInput: userInput });
    else worker.send({ domains: domains.slice(i, i + remainder), userInput: userInput });
  }
}

function childProcess() {
  process.on('message', data => {

    // ToDo conditional pipes
    // tried detour but it returns BufferStream :(

    if (data.userInput.mode == 1) { // simple scanner
      StringStream.from(data.domains)
        // .setOptions({ maxParallel: numCPUs })
        .pipe(needleYo)
        .pipe(processResponse)
        .pipe(fs.createWriteStream('result.csv'))
        .on('finish', function() { process.exit(1); });
    }

    else if (data.userInput.mode == 6) { // subdomain scanner
      StringStream.from(data.domains)
        .setOptions({ maxParallel: numCPUs })
        .pipe(findSub)
        .pipe(oneByOne)
        .pipe(needleYo)
        .pipe(processResponse)
        .pipe(fs.createWriteStream('result.csv'))
        .on('finish', function() { process.exit(1); });
    }

    else if(data.userInput.mode == 7){ // subdomain full scanner
       StringStream.from(data.domains)
        .setOptions({ maxParallel: numCPUs })
        .pipe(findSub)
        .pipe(oneByOne)
        .pipe(crlfpayload)
        .pipe(orpayload)
        .pipe(needleYo)
        .pipe(cnameresponse)
        .pipe(processResponse)
        .pipe(fs.createWriteStream('result.csv'))
        .on('finish', function() { process.exit(1); });
    }

     else if (data.userInput.mode == 3) { // crlf
      StringStream.from(data.domains)
        .setOptions({ maxParallel: numCPUs })
        .pipe(crlfpayload)
        .pipe(needleYo)
        .pipe(processResponse)
        .pipe(fs.createWriteStream('result.csv'))
        .on('finish', function() { process.exit(1); });

    } else if (data.userInput.mode == 4) { // open redirect
      StringStream.from(data.domains)
        .setOptions({ maxParallel: numCPUs })
        .pipe(orpayload)
        .pipe(needleYo)
        .pipe(processResponse)
        .pipe(fs.createWriteStream('result.csv'))
        .on('finish', function() { process.exit(1); });
    } else if (data.userInput.mode == 2) { // cname
      StringStream.from(data.domains)
        .setOptions({ maxParallel: numCPUs })
        .pipe(needleYo)
        .pipe(cnameresponse)
        .pipe(processResponse)
        .pipe(fs.createWriteStream('result.csv'))
        .on('finish', function() { process.exit(1); });
    } else {
                                        // full domain scan
      StringStream.from(data.domains)
        .setOptions({ maxParallel: numCPUs })
        .pipe(findSub)
        .pipe(oneByOne)
        .pipe(crlfpayload)
        .pipe(orpayload)
        .pipe(needleYo)
        .pipe(cnameresponse)
        .pipe(processResponse)
        .pipe(fs.createWriteStream('result.csv'))
        .on('finish', function() { process.exit(1); });

    }
  });
}


const findSub = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  async transform(chunk, encoding, callback) {
    chunk = chunk.toString().split(/\n/).filter(Boolean);
    for (let i = 0; i < chunk.length; i++) {
      let sds = await findSubdomains(chunk[i]);
      this.push(sds);
    }
    callback();
  }
});

const oneByOne = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  async transform(chunk, encoding, callback) {
    for (let i = 0; i < chunk.length; i++) {
      this.push(chunk[i])
    }
    callback();
  }
});

const crlfpayload = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  async transform(chunk, encoding, callback) {
    // read payload file
    // create url with payload and push
    fs.createReadStream(crlf_payload_file)
      .pipe(new BufferStream)
      .toStringStream()
      .lines()
      .map(x => {
        console.log(chunk + x)
        this.push(chunk + x);
      })
  }
});


const orpayload = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  async transform(chunk, encoding, callback) {
    fs.createReadStream(open_rediect_payload_file)
      .pipe(new BufferStream)
      .toStringStream()
      .lines()
      .map(x => {
        console.log(chunk + x)
        this.push(chunk + x);
      })
  }
});


const cnameresponse = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  async transform(chunk, encoding, callback) {
    // console.log(chunk)
   fs.createReadStream(cname_takeover_file)
      .pipe(new BufferStream)
      .toStringStream()
      .CSVParse({header: true})
      .map(x => {
        if(chunk.host.includes(x.cname)){
          if(chunk.body.includes(x.string)){
            chunk.CNAME = true;
            delete chunk.body;
            this.push(chunk);
          } else { delete chunk.body; this.push(chunk)};
        } else { delete chunk.body;this.push(chunk);}
      })
  }
});

const needleYo = new Transform({
  readableObjectMode: true,
  writableObjectMode: true,
  async transform(chunk, encoding, callback) {
    try {
      let response = await needle('get', 'https://' + chunk, { parse: true });
      this.push({ host: response.host || response.hostname || 'https://' + chunk, port: response.port, body: response.body ,status: response.statusCode, headers: response.headers, location: response.location });
      response = await needle('get', 'http://' + chunk, { parse: true });
      this.push({ host: response.host || response.hostname || 'http://' + chunk, port: response.port, body: response.body, status: response.statusCode, headers: response.headers, location: response.location });
      callback();
    } catch (err) {
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
    process.exit(1)
  }

  const target = a;
  const domain = clearUrl(target)

  let response
  try {
    response = await getRawResponse(domain);
  } catch (err) {
    console.log(err)
    console.log(`Information not available! (${err.statusCode})`)
    return process.exit(1)
  }

  const jsonData = JSON.parse(`[${response.trim().replace(/}{/g, '},{')}]`)
  const subdomains = Array.from(new Set(jsonData.map(_ => _.name_value))).sort((a, b) => a > b)
  return subdomains;
  // for (const _ of subdomains) console.log(`[+] ${_}`)
}
