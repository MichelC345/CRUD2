const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

function initialize(passport) {
    const authenticateUser = (user, pass, done) => {
        pool.query(
            `SELECT * FROM dadoscrud2 WHERE usuario = $1`,
            [user],
            (err, results) => {
                if (err) {
                    throw err;
                }

                console.log(results.rows);

                if (results.rows.length > 0) {
                    const user = results.rows[0]; //dados do usuário no banco de dados

                    bcrypt.compare(pass, user.senha, (err, isMatch) => {
                        if (err) {
                            throw err;
                        }

                        if (isMatch) {
                            return done(null, user);
                        }else {
                            return done(null, false, {message: "Senha não está correta"});
                        }
                    });
                }else {
                    return done(null, false, {message: "Usuário não registrado"});
                }
            }
        );
    };


    passport.use(
        new LocalStrategy({
            usernameField: "user",
            passwordField: "pass"
        },
        authenticateUser
        )
    );

    passport.serializeUser((user, done) => done(null, user.id));

    passport.deserializeUser((id, done)=> {
        pool.query(
            `SELECT * FROM dadoscrud2 WHERE id = $1`, [id], (err, results)=>{
                if (err) {
                    throw err;
                }
                return done(null, results.rows[0]);
            }
        );
    });
}

module.exports = initialize;