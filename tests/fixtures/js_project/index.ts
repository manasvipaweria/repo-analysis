import express from 'express';
import _ from 'lodash';

const app = express();
app.get('/', (req, res) => {
    // intentional vulnerability: eval
    eval(req.query.cmd);
    res.send('Hello');
});
app.listen(3000);
