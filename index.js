import crypto from 'node:crypto';
import fs from 'node:fs/promises';

function receiveArq(arr){
    const receiveArr = [];
    for(const current of arr){
        const hash = crypto.createHash('sha256');
        hash.update(current);
        const result = hash.digest('hex');
        receiveArr.push(result);
    }
    console.log(receiveArr[0])
    console.log('-----------')
    console.log(receiveArr[1])
    return receiveArr;
}

//receiveArq(['teste','testando'])

function genereteToken(length){
    if(length >= 40){
        const token = crypto.randomBytes(length, (err, buffer)=>{
            if(err) console.log('Erro ao gerar token');
            return buffer.toString('hex');
        })
    }
    
    const token = crypto.randomBytes(length).toString('hex');
    return token;
}

// console.log(genereteToken(41))

function genereteHmac(content, key){
    let contentCorrect = content;
    let correctKey = key;
    if(typeof content !== 'string') { contentCorrect = JSON.stringify(content) }
    if(typeof key !== 'string') { correctKey = JSON.stringify(key) }
    const protectHash = crypto
        .createHmac('sha256', correctKey)
        .update(contentCorrect)
        .digest('hex');
    
    //console.log(protectHash);
    return protectHash; 
}

// genereteHmac('Teste', 'chave');

function genereteAssignature(objectReceive){
    const assignatureWork = crypto.createHash('sha256');
    const keysObj = Object.keys(objectReceive);

    for(const currentInfo of keysObj){
        if(currentInfo === 'admin') continue;
        assignatureWork.update(JSON.stringify(objectReceive[currentInfo]))
    }
    const assignature = assignatureWork.digest('hex');

    const createSecurityAssignature = crypto
        .createHmac('sha256', assignature)
        .update(JSON.stringify(objectReceive.admin))
        .digest('hex');

    console.log(createSecurityAssignature)
}
 /*
genereteAssignature({
    name: 'Abner',
    age: 21,
    admin: true
});
*/

function genericJWT(object, genericContent){
    const stringObj = JSON.stringify(object);

    const assignJWT = crypto
        .createHmac('sha256', stringObj)
        .update(genericContent)
        .digest('hex');

    console.log(assignJWT)
    return assignJWT;
}

/*
genericJWT({
    id: 1,
    name: 'admin'
}, 'Conteudo generico')
*/

const users = [];
// const randomPassword = genereteHmac('Abner', 12345)
// users.push({name: 'Abner', password: randomPassword });
   
function genericLogin(usersArg, name, passwordArg){
    const unknownUser = genereteHmac(name, passwordArg);
    const user = usersArg.find(e => {
        return e.name == name && e.password == unknownUser
    });

    if(user) return console.log('Login realizado!');

    console.log('Senha inválida!')
}
    
// genericLogin(users, 'Abner', 12345)

function teste(secretKey){
    const secret = crypto
        .createHmac('sha256', secretKey)
        .update('teste')
        .digest('hex')

    console.log(secret);
    return secret;
}

//teste('123')
