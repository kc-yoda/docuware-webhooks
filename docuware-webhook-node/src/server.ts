import express, { Application, Request, Response } from 'express';
import docuware, { verification } from './webhooks/docuware';

const app: Application = express();
const port = process.env.PORT || 3000;

app.use(express.json({
        verify: verification
}));

app.get('/', (req: Request, res: Response) => {
    res.send(JSON.stringify({status: 'ok', version: '0.1'}));
});

app.use("/webhooks/docuware", docuware);

app.listen(port, () => {
    console.log(`Server is up and running on http://localhost:${port}`);
});
