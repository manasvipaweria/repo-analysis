/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    {
      name: 'no-circular',
      severity: 'warn',
      comment: 'Warns about circular dependencies.',
      from: {},
      to: { circular: true }
    },
    {
      name: 'no-orphans',
      severity: 'info',
      comment: 'Warns about orphan modules.',
      from: { orphan: true },
      to: {}
    }
  ],
  options: {
    doNotFollow: {
      path: 'node_modules'
    },
    exclude: {
      path: 'node_modules'
    },
    tsPreCompilationDeps: true,
    tsConfig: {
      fileName: 'tsconfig.json'
    }
  }
};
