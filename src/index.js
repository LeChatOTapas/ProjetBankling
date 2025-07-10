const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt'); // Pour le hachage des mots de passe

const app = express();
const port = 3000;

// Middleware pour analyser les requêtes JSON
app.use(bodyParser.json());

// Connecter à la base de données MySQL
const db = mysql.createConnection({
    host: 'localhost', // Remplacez par l'adresse IP de votre base de données
    user: 'root', // Remplacez par votre nom d'utilisateur MySQL
    password: 'root', // Remplacez par votre mot de passe MySQL
    database: 'bankling' // Remplacez par le nom de votre base de données
});

db.connect(err => {
    if (err) {
        console.error('Erreur de connexion à la base de données:', err);
        return;
    }
    console.log('Connecté à la base de données MySQL');
});

// Route de base pour vérifier que le serveur fonctionne
app.get('/', (req, res) => {
    res.send('API REST pour ComputerCraft');
});

// Route pour obtenir des données depuis la table users
app.get('/data', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ data: results });
    });
});

// Route pour ajouter un utilisateur à la table users
app.post('/users', (req, res) => {
    const { pseudo, identifiant, mot_de_passe, solde } = req.body;
    if (!pseudo || !identifiant || !mot_de_passe || solde === undefined) {
        return res.status(400).json({ error: 'Tous les champs sont requis' });
    }

    const hashedPassword = bcrypt.hashSync(mot_de_passe, 10);
    const query = 'INSERT INTO users (pseudo, identifiant, mot_de_passe, solde) VALUES (?, ?, ?, ?)';
    db.query(query, [pseudo, identifiant, hashedPassword, solde], (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: 'Utilisateur ajouté avec succès', id: result.insertId });
    });
});

// Route pour supprimer un utilisateur par ID
app.delete('/users/:id', (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM users WHERE id = ?';
    db.query(query, [id], (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }
        res.status(200).json({ message: 'Utilisateur supprimé avec succès' });
    });
});

// Route pour modifier un utilisateur par ID
app.put('/users/:id', (req, res) => {
    const { id } = req.params;
    const { pseudo, identifiant, mot_de_passe, solde } = req.body;
    if (!pseudo && !identifiant && !mot_de_passe && solde === undefined) {
        return res.status(400).json({ error: 'Au moins un champ est requis pour la mise à jour' });
    }

    const fields = [];
    const values = [];

    if (pseudo) {
        fields.push('pseudo = ?');
        values.push(pseudo);
    }
    if (identifiant) {
        fields.push('identifiant = ?');
        values.push(identifiant);
    }
    if (mot_de_passe) {
        const hashedPassword = bcrypt.hashSync(mot_de_passe, 10);
        fields.push('mot_de_passe = ?');
        values.push(hashedPassword);
    }
    if (solde !== undefined) {
        fields.push('solde = ?');
        values.push(solde);
    }

    values.push(id);

    const query = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
    db.query(query, values, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }
        res.status(200).json({ message: 'Utilisateur modifié avec succès' });
    });
});

// Route pour la connexion des utilisateurs
app.post('/login', (req, res) => {
    const { identifiant, mot_de_passe } = req.body;
    if (!identifiant || !mot_de_passe) {
        return res.status(400).json({ error: 'Identifiant et mot de passe sont requis' });
    }

    const query = 'SELECT * FROM users WHERE identifiant = ?';
    db.query(query, [identifiant], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }

        const user = results[0];
        const passwordMatch = bcrypt.compareSync(mot_de_passe, user.mot_de_passe);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Mot de passe incorrect' });
        }

        const isAdmin = identifiant === 'admin';
        res.status(200).json({ message: 'Connexion réussie', user: { pseudo: user.pseudo, solde: user.solde, isAdmin } });
    });
});

// Démarrer le serveur
app.listen(port, () => {
    console.log(`Serveur en cours d'exécution sur http://localhost:${port}`);
});