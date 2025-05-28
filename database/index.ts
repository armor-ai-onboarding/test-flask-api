router.get<{}, MessageResponse>('/welcome', (req, res) => {
  res.json({
    message: 'Welcome to our API! 🚀',
    timestamp: new Date().toISOString(),
    status: 'success'
  });
});
