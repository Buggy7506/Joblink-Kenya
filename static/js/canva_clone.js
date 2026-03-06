(function () {
  function init() {
    if (!window.fabric) {
      return;
    }

    const canvas = new fabric.Canvas('designCanvas', {
      preserveObjectStacking: true,
      selection: true,
      backgroundColor: '#ffffff',
    });

    const state = {
      tool: 'select',
      history: [],
      redo: [],
      drawingColor: '#5b7cfa',
      fontSize: 34,
    };

    const colorPicker = document.getElementById('colorPicker');
    const fontSize = document.getElementById('fontSize');
    const uploadImage = document.getElementById('uploadImage');
    const layerList = document.getElementById('layerList');
    const statusBadge = document.getElementById('statusBadge');

    function setStatus(text) {
      statusBadge.textContent = text;
    }

    function refreshLayers() {
      layerList.innerHTML = '';
      const objects = canvas.getObjects().slice().reverse();
      objects.forEach((obj, index) => {
        const li = document.createElement('li');
        const button = document.createElement('button');
        const type = obj.type || 'layer';
        button.textContent = `${index + 1}. ${type}`;
        if (obj === canvas.getActiveObject()) {
          button.classList.add('is-selected');
        }
        button.addEventListener('click', function () {
          canvas.setActiveObject(obj);
          canvas.requestRenderAll();
          refreshLayers();
        });
        li.appendChild(button);
        layerList.appendChild(li);
      });
    }

    function snapshot() {
      state.history.push(JSON.stringify(canvas.toDatalessJSON()));
      if (state.history.length > 50) state.history.shift();
      state.redo = [];
      refreshLayers();
    }

    function restore(serialized, statusText) {
      canvas.loadFromJSON(serialized, function () {
        canvas.requestRenderAll();
        refreshLayers();
        setStatus(statusText);
      });
    }

    function setTool(tool) {
      state.tool = tool;
      document.querySelectorAll('.tool-btn').forEach((btn) => {
        btn.classList.toggle('is-active', btn.dataset.tool === tool);
      });

      canvas.isDrawingMode = tool === 'draw';
      canvas.selection = tool === 'select';
      canvas.forEachObject((obj) => {
        const selectable = tool === 'select';
        obj.selectable = selectable;
        obj.evented = selectable;
      });
      setStatus(`Tool: ${tool}`);
    }

    function addText() {
      const text = new fabric.IText('Double click to edit', {
        left: 140,
        top: 120,
        fill: state.drawingColor,
        fontSize: state.fontSize,
        fontFamily: 'Inter, sans-serif',
      });
      canvas.add(text);
      canvas.setActiveObject(text);
      snapshot();
    }

    function addRect() {
      const rect = new fabric.Rect({
        left: 120,
        top: 120,
        fill: state.drawingColor,
        width: 260,
        height: 160,
        rx: 8,
        ry: 8,
      });
      canvas.add(rect);
      canvas.setActiveObject(rect);
      snapshot();
    }

    function addCircle() {
      const circle = new fabric.Circle({
        left: 170,
        top: 150,
        radius: 90,
        fill: state.drawingColor,
      });
      canvas.add(circle);
      canvas.setActiveObject(circle);
      snapshot();
    }

    function setPreset(preset) {
      const presets = {
        resume: [1240, 1754],
        instagram: [1080, 1080],
        linkedin: [1584, 396],
        presentation: [1366, 768],
      };
      const [width, height] = presets[preset] || presets.instagram;
      canvas.setWidth(width);
      canvas.setHeight(height);
      canvas.calcOffset();
      canvas.requestRenderAll();
      setStatus(`Preset: ${preset} (${width}x${height})`);
    }

    document.querySelectorAll('.tool-btn').forEach((btn) => {
      btn.addEventListener('click', function () {
        const tool = btn.dataset.tool;
        setTool(tool);
        if (tool === 'text') addText();
        if (tool === 'rect') addRect();
        if (tool === 'circle') addCircle();
      });
    });

    document.querySelectorAll('.preset-btn').forEach((btn) => {
      btn.addEventListener('click', function () {
        setPreset(btn.dataset.preset);
      });
    });

    colorPicker.addEventListener('input', function () {
      state.drawingColor = this.value;
      canvas.freeDrawingBrush.color = this.value;
      const active = canvas.getActiveObject();
      if (active && active.set) {
        if (active.fill !== undefined) active.set('fill', this.value);
        if (active.stroke !== undefined) active.set('stroke', this.value);
        canvas.requestRenderAll();
        snapshot();
      }
    });

    fontSize.addEventListener('input', function () {
      state.fontSize = Number(this.value);
      const active = canvas.getActiveObject();
      if (active && active.type === 'i-text') {
        active.set('fontSize', state.fontSize);
        canvas.requestRenderAll();
        snapshot();
      }
    });

    uploadImage.addEventListener('change', function (event) {
      const file = event.target.files && event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function (loadEvent) {
        fabric.Image.fromURL(loadEvent.target.result, function (img) {
          img.set({ left: 100, top: 100, scaleX: 0.45, scaleY: 0.45 });
          canvas.add(img);
          canvas.setActiveObject(img);
          snapshot();
          setStatus('Image added');
        });
      };
      reader.readAsDataURL(file);
    });

    document.getElementById('undoBtn').addEventListener('click', function () {
      if (!state.history.length) return;
      const current = JSON.stringify(canvas.toDatalessJSON());
      const prev = state.history.pop();
      state.redo.push(current);
      restore(prev, 'Undo applied');
    });

    document.getElementById('redoBtn').addEventListener('click', function () {
      if (!state.redo.length) return;
      const next = state.redo.pop();
      state.history.push(JSON.stringify(canvas.toDatalessJSON()));
      restore(next, 'Redo applied');
    });

    document.getElementById('deleteBtn').addEventListener('click', function () {
      const active = canvas.getActiveObject();
      if (!active) return;
      canvas.remove(active);
      canvas.discardActiveObject();
      canvas.requestRenderAll();
      snapshot();
      setStatus('Element deleted');
    });

    document.getElementById('duplicateBtn').addEventListener('click', function () {
      const active = canvas.getActiveObject();
      if (!active) return;
      active.clone(function (cloned) {
        cloned.set({ left: (active.left || 0) + 24, top: (active.top || 0) + 24 });
        canvas.add(cloned);
        canvas.setActiveObject(cloned);
        canvas.requestRenderAll();
        snapshot();
      });
    });

    document.getElementById('downloadBtn').addEventListener('click', function () {
      const url = canvas.toDataURL({ format: 'png', multiplier: 2 });
      const link = document.createElement('a');
      link.download = `joblink-design-${Date.now()}.png`;
      link.href = url;
      link.click();
      setStatus('PNG exported');
    });

    canvas.on('object:modified', snapshot);
    canvas.on('object:added', refreshLayers);
    canvas.on('selection:created', refreshLayers);
    canvas.on('selection:updated', refreshLayers);
    canvas.on('selection:cleared', refreshLayers);

    canvas.freeDrawingBrush = new fabric.PencilBrush(canvas);
    canvas.freeDrawingBrush.width = 4;
    canvas.freeDrawingBrush.color = state.drawingColor;

    setPreset('instagram');
    setTool('select');
    snapshot();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
