import crypto from 'node:crypto';
import fsPromises from 'node:fs/promises';
import fs, { readFile } from 'node:fs';
import path from 'node:path';

const objFileAuthentic = {
    calcBytes: (bytes)=>{
        if(bytes === 0) return '0 Bytes';

            let k = 1024;
            const tamanhos = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

            const i = Math.floor(Math.log(bytes) / Math.log(k));

            return { 
                result: parseFloat((bytes / Math.pow(k, i)).toFixed(2)),
                measure: tamanhos[i]
            }
        },

    fileAuthentic: async (pathReceive, secretKey = 'Santos')=>{
        try{
            if(!(await fsPromises.stat(pathReceive)).isFile()){
                return console.log('Era arquivo!')     
            }

            if(!fs.existsSync(pathReceive)){
                return console.log('Não existe nada nesse caminho!')
            }
            
                const hashAndHmac = new Map();
                const allFiles = await fsPromises.readdir(pathReceive);
                const filterFiles = await Promise.all(
                    allFiles.map(async (current) => {
                        const pathImplemented = path.join(pathReceive, current);
                        const file = (await fsPromises.stat(pathImplemented)).isFile() ? pathImplemented : null;
                        return file;
                    })
                )

                for(const readFileAc of filterFiles){
                    if(readFileAc === null) continue;
                    const readFileAnalyzed = await fsPromises.stat(readFileAc);
                    const readFileCompleted = objFileAuthentic.calcBytes(readFileAnalyzed.size)

                    if(['MB','GB','TB'].find(e => e === readFileCompleted.measure)){
                        await new Promise((resolve, reject) => {
                            const streamRead = fs.createReadStream(readFileAc);
                            const hmac = crypto.createHmac('sha256', secretKey);
                            const hash = crypto.createHash('sha256');

                            streamRead.on('data', (chunk)=> { 
                                hmac.update(chunk);
                                hash.update(chunk);
                            });

                            streamRead.on('end', ()=> {
                                const resultHmac = hmac.digest('hex');
                                const resultHash = hash.digest('hex');
                                hashAndHmac.set(resultHmac, []);
                                hashAndHmac.get(resultHmac).push(resultHash, readFileAc)
                                resolve()
                            });

                            streamRead.on('error', (err)=>{
                                reject(err)
                            })
                        })
                        continue;
                    }
                    const andFile = (await fsPromises.readFile(readFileAc)).toString('hex');
                    const hmacAndFile = crypto
                        .createHmac('sha256', secretKey)
                        .update(andFile)
                        .digest('hex');
                    
                    const hashAndFile = crypto
                        .createHash('sha256')
                        .update(andFile)
                        .digest('hex');

                    hashAndHmac.set(hmacAndFile, [])
                    hashAndHmac.get(hmacAndFile).push(hashAndFile, readFileAc);
                }

                const allKeys = [...hashAndHmac.keys()];
                for(const currentKey of allKeys){
                    await fsPromises.mkdir('./logs', {
                        recursive: true
                    })

                    if(fs.existsSync('./logs/log.sig')){
                        const existingContent = await fsPromises.readFile('./logs/log.sig', 'utf-8');
                        const lineFind = existingContent.split(',').find(e => {
                            return e.trim() === `arquivo: ${hashAndHmac.get(currentKey)[1]}`
                        });
                        if(lineFind) {
                            continue};
                    }
                    const content = 
                    `
    algoritmo: ${hashAndHmac.get(currentKey)[0]},
    arquivo: ${hashAndHmac.get(currentKey)[1]},
    assinatura: ${currentKey}
                    `
                    await fsPromises.appendFile('./logs/log.sig', content);
                }
            } catch(err){
                console.log(`Erro: ${err}`)
            }
        },
        
    fileRead: async (file = './logs/log.sig', fileReceive, secretKey = 'Santos')=>{
        if(!(await fsPromises.stat(fileReceive)).isFile()){
            return console.log('Apenas arquivos são aceitos!')
        }
        if(!(await fs.existsSync(file))){
            return console.log('Não existe nada nesse caminho!')
        }
        const content = await fsPromises.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const hashAndHmacReceive = new Map();

        const receiveFile = await fsPromises.stat(fileReceive);
        const sizeFile = objFileAuthentic.calcBytes(receiveFile.size) 
        const confirm = [];

        if(['MB','GB','TB'].find(e => e === sizeFile.measure)){
            await new Promise((resolve, reject) =>{
                const currentResult = fs.createReadStream(fileReceive);
                const hashReceive = crypto.createHash('sha256');
                const hmacReceive = crypto.createHmac('sha256', secretKey);
                
                currentResult.on('data', (chunk)=> {
                    hashReceive.update(chunk);
                    hmacReceive.update(chunk);
                });
                
                currentResult.on('end', ()=>{
                    const digest = hmacReceive.digest('hex');
                    hashAndHmacReceive.set( digest, []);
                    hashAndHmacReceive.get(digest).push(hashReceive.digest('hex'), fileReceive);
                    resolve()
                });
            })
        }
        
        if(['Bytes', 'KB'].find(e => e === sizeFile.measure)){
            const resultReceive = await fsPromises.readFile(fileReceive);
            
            const hashReceive = await crypto
                .createHmac('sha256')
                .update(resultReceive)
                .digest('hex');

            const hmacReceive = await crypto
                .createHmac('sha256', secretKey)
                .update(resultReceive)
                .digest('hex');

            hashAndHmacReceive.set(hmacReceive, [])
            hashAndHmacReceive.get(hmacReceive).push(hashReceive, fileReceive)
        }

        const sameHmac = lines.find(e => {
            const assignature = e.includes('assinatura');
            if(assignature){
                const value = e.split(':');
                const hmac = [...hashAndHmacReceive.keys()];
                const bufferHmac = Buffer.from(value[1].trim(), 'hex');
                const bufferHmacReceive = Buffer.from(hmac[0], 'hex');

                if(
                    bufferHmac.length === bufferHmacReceive.length 
                    && 
                    crypto.timingSafeEqual(bufferHmac, bufferHmacReceive))
                    {
                        return true
                    }
            }
        });
        const sameHash = lines.find(e => {
            const algorithm = e.includes('algoritmo');
            if(algorithm){
                const value = e.split(':');
                const hmac = [...hashAndHmacReceive.keys()];
                const hash = hashAndHmacReceive.get(hmac[0]);

                const bufferHmac = Buffer.from(value[1].trim(), 'hex');
                const bufferHmacReceive = Buffer.from(hash[0], 'hex');

                if(
                    bufferHmac.length === bufferHmacReceive.length 
                    && 
                    crypto.timingSafeEqual(bufferHmac, bufferHmacReceive))
                    {
                        return true
                    }
            }
        });

        if(sameHash && sameHmac){
            console.log('Esse é uma arquivo integro.')
        }
    }
}

//objFileAuthentic.fileAuthentic('./testando', 'Santos')
objFileAuthentic.fileRead('./logs/log.sig', './video_inteligente.mp4', 'Santos');