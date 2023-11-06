const express = require("express");
const app = express();
const { pool } = require("./dbConfig"); //configuração feita em dbConfig para conectar-se ao postgre
const bcrypt = require("bcrypt"); //criptografia de senha
const session = require("express-session"); //sessão de login
const flash = require("express-flash"); //mostrar mensagens
const passport = require("passport"); //autenticação de senha
const initializePassport = require("./passportConfig"); //configuração da autenticação
const moment = require("moment"); //formatação de data

initializePassport(passport);

const PORT = process.env.PORT || 4000;

/*app.get("/", (req, res) => {
    res.send("Hello");
}); */

app.set("view engine", "ejs"); //visualizar documentos das extensões .ejs

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`); //console imprime a porta em que o servidor está funcionando
})

app.use(express.static("public")); //pegar css
app.use(express.urlencoded({extended: false})); //permitir armazenar respostas do formulário em variáveis

app.use(
    session({
        secret: "secret",
        resave: false,
        saveUninitialized: false
    })
);

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

app.get("/", checkAuthenticated, (req, res) => { //site padrão será o index.ejs
    res.render("index");
});

app.get("/cadastro", checkAuthenticated, (req, res) => { //tela de cadastro em localhost:4000/cadastro
    res.render("cadastro");
});

app.get("/usuario", checkNotAuthenticated, (req, res) => { //tela do usuário em localhost:4000/usuario
    res.render("usuario", {
        user: req.user.usuario,
        phone: req.user.telefone,
        date: moment(req.user.data_nasc).format('DD/MM/YYYY')
    });
});

app.post("/cadastro", async (req, res) => {
    let {user, pass, pass2, phone, date} = req.body;
    //regExp = expressão regular para validar telefone
    //construída com a ferramenta Simple Regex Language
    //fonte: https://pt.stackoverflow.com/questions/189187/express%C3%A3o-regular-em-javascript-para-telefone-com-ddi/189192
    var regExp = /[0-9]{2}[0-9]{2}[0-9]{4,5}[0-9]{4}$/;

    console.log({ //dados inseridos são mostrados no console
        user,
        pass,
        pass2,
        phone,
        date
    });
    
    let errors = [];

    if (!user || !pass || !pass2 || !phone || !date) {
        errors.push({message: "Por favor preencha todos os campos."});
    }
    if (user.length < 4) {
        errors.push({message: "Usuário deve ter no mínimo 4 caracteres"});
    }
    if (pass.length < 6) {
        errors.push({message: "A senha deve ter no mínimo 6 caracteres."});
    }
    if (pass != pass2) {
        errors.push({message: "As senhas não procedem."});
    }
    if (!regExp.test(phone)) {
        errors.push({message: "Telefone inserido é inválido."});
        errors.push({message: "Formato aceito: código do páis/DDD/telefone"})
        errors.push({message: "Exemplo de telefone válido: 5545233215454"});
    }

    if (errors.length > 0) { //erros encontrados?
        res.render("cadastro", {errors}); //permanece na página e relata os erros
    }else { //formulário aceito

        let hashedPass = await bcrypt.hash(pass, 10); //criptografia
        console.log(hashedPass);

        pool.query( //requisição ao banco de dados verificando se já há usuário com o nome
            `SELECT * FROM public.dadoscrud2
            WHERE usuario = $1`,
            [user],
            (err, results) => {
                if (err) {
                    throw err;
                }
                console.log("Usuário com mesmo nome encontrado aqui");
                console.log(results.rows);

                if (results.rows.length > 0) { //usuário já cadastrado?
                    errors.push({ message: "Este usuário já está registrado." });
                    res.render("cadastro", { errors }); //permanece na tela e relata o erro
                }else {
                    pool.query ( //requisiçao ao banco de dados para verificar se já há um telefone igual
                    `SELECT * FROM public.dadoscrud2
                    WHERE telefone = $1`,
                    [phone], //parâmetro $1 = telefone inserido
                    (err, results) => {
                        if (err) {
                            throw err;
                        }
                        console.log("Usuário com mesmo telefone encontrado aqui");
                        console.log(results.rows);

                        if (results.rows.length > 0) { //telefone já cadastrado?
                            errors.push({ message: "O telefone inserido já está registrado." });
                            res.render("cadastro", { errors }); //permanece na tela e relata o erro
                        }else { //cadastro pode ser efetuado
                            pool.query ( //requisição ao banco de dados para inserção dos dados
                                `INSERT INTO public.dadoscrud2 (usuario, senha, telefone, data_nasc)
                                VALUES ($1, $2, $3, $4)
                                RETURNING id, senha`, //returning - forma de atribuir ID
                                [user, hashedPass, phone, date], //parâmetros $1, $2, $3, $4. Portanto, senha inserida será a criptografada
                                (err, results) => {
                                    if (err) {
                                        throw err;
                                    }
                                    console.log(results.rows);
                                    req.flash("success_msg", "Cadastro feito com sucesso.");
                                    res.redirect("/");
                                }
                            );
                        }
                    }
                    );
                }
            }
        );
    }
});

app.post("/usuario", (req, res) => { //deletar conta

    let {passdel} = req.body; //recebe senha do input
    let userdel = req.user.usuario; //recebe usuário diretamente do BD
    console.log({userdel, passdel});

    pool.query( `SELECT * FROM public.dadoscrud2
    WHERE usuario = $1`,
    [userdel], //parâmetro $1
    (err, results) => {
        if (err) {
            throw err;
        }
        console.log("usuário está aqui:");
        console.log(results.rows);
        if (results.rows.length == 0) { //usuário já cadastrado?
            req.flash("error", "Usuário não encontrado");
            res.redirect("/usuario");
        }else {//usuário existe
            const user = results.rows[0];

            bcrypt.compare(passdel, user.senha, (err, isMatch) => { //usa o bcrypt para comparar a senha inserida com a senha criptografada
                if (err) {
                    throw err;
                }
                
                const planName = req.body.planName;

                if (isMatch) {
                    pool.query(`DELETE FROM dadoscrud2 WHERE usuario = '${user.usuario}'`),
                    [planName],
                    (err, res) => {
                        if (err) {
                            throw err;
                        }
                        console.log(res);
                    }
                    //return done(null, user);
                    req.logOut(function(err) {
                        if (err) {throw err;}
                        req.flash("success_msg", "Usuário excluído com sucesso");
                        res.redirect("/"); //volta à tela inicial
                    });
                }else {
                    //return done(null, false, {message: "Senha não está correta"});
                    req.flash("error", "Senha inválida");
                    res.redirect("/usuario");
                }
            })
        }
        
    }
    )
});

app.post( //procedimentos para autenticar o usuário no login
    "/", 
    passport.authenticate("local", {
        successRedirect: "/usuario",
        failureRedirect: "/",
        failureFlash: true
    })
    )

    
app.get("/logout", (req, res) => {
    req.logOut(function(err) {
        if (err) {throw err;}
        req.flash("success_msg", "Você acabou de deslogar");
        res.redirect("/"); //volta à tela inicial
    });
});

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/usuario"); //caso esteja autenticado vai para a tela do usuário
    }
    next(); //senão, vai para a tela que o usuário está tentando ir
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }

    req.flash("error", "Você não está logado");
    res.redirect("/");
}